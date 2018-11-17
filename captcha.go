package apicaptcha

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-apibox/api"
	"github.com/go-apibox/cache"
	"github.com/go-apibox/utils"
	"github.com/dchest/captcha"
)

type CaptchaConfig struct {
	identifier   string
	maxFailCount int
}

type Captcha struct {
	app      *api.App
	disabled bool
	inited   bool

	getAction  string
	showAction string

	captchaLength int
	imgWidth      int
	imgHeight     int

	captchaMatcher *utils.Matcher
	captchaConfigs map[string]*CaptchaConfig
	captchaCache   *cache.Cache
}

func NewCaptcha(app *api.App) *Captcha {
	app.Error.RegisterGroupErrors("captcha", ErrorDefines)

	ca := new(Captcha)
	ca.app = app

	cfg := app.Config
	disabled := cfg.GetDefaultBool("apicaptcha.disabled", false)
	ca.disabled = disabled
	if disabled {
		return ca
	}

	ca.init()
	return ca
}

func (ca *Captcha) init() {
	if ca.inited {
		return
	}

	app := ca.app
	cfg := app.Config
	getAction := cfg.GetDefaultString("apicaptcha.get_action", "GetCaptcha")
	showAction := cfg.GetDefaultString("apicaptcha.show_action", "ShowCaptcha")
	captchaLength := cfg.GetDefaultInt("apicaptcha.captcha_length", 4)
	imgWidth := cfg.GetDefaultInt("apicaptcha.image_width", 180)
	imgHeight := cfg.GetDefaultInt("apicaptcha.image_height", 60)

	d, oldd := string([]byte{0x0}), cfg.Delimiter
	cfg.Delimiter = d // action中可能有.号，会冲突
	captchaActionMap := cfg.GetDefaultMap("apicaptcha"+d+"actions", map[string]interface{}{})
	captchaActions := make([]string, 0, len(captchaActionMap))
	captchaConfigs := make(map[string]*CaptchaConfig)
	for action, _ := range captchaActionMap {
		captchaActions = append(captchaActions, action)
		captchaConfig := new(CaptchaConfig)
		pre := "apicaptcha" + d + "actions" + d + action + d
		captchaConfig.identifier = cfg.GetDefaultString(pre+"identifier", "")
		captchaConfig.maxFailCount = cfg.GetDefaultInt(pre+"max_fail_count", 0)
		captchaConfigs[action] = captchaConfig
	}
	cfg.Delimiter = oldd

	ccMatcher := utils.NewMatcher().SetWhiteList(captchaActions)

	ca.getAction = getAction
	ca.showAction = showAction

	ca.captchaLength = captchaLength
	ca.imgWidth = imgWidth
	ca.imgHeight = imgHeight

	ca.captchaMatcher = ccMatcher
	ca.captchaConfigs = captchaConfigs
	ca.captchaCache = cache.NewCacheEx(time.Duration(3600)*time.Second, time.Duration(60)*time.Second)

	ca.inited = true
}

func (ca *Captcha) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if ca.disabled {
		next(w, r)
		return
	}

	c, err := api.NewContext(ca.app, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	action := c.Input.GetAction()

	switch action {
	case ca.getAction:
		id := captcha.NewLen(ca.captchaLength)
		result := map[string]string{"CaptchaId": id}
		api.WriteResponse(c, result)
		return

	case ca.showAction:
		id := r.FormValue("CaptchaId")
		if id == "" {
			http.NotFound(w, r)
			return
		}

		imgWidth, imgHeight := ca.imgWidth, ca.imgHeight
		if width := r.Form.Get("Width"); width != "" {
			if w, err := strconv.Atoi(width); err == nil && w < 300 {
				imgWidth = w
			}
		}
		if height := r.Form.Get("Height"); height != "" {
			if h, err := strconv.Atoi(height); err == nil && h < 300 {
				imgHeight = h
			}
		}
		if r.FormValue("Reload") != "" {
			captcha.Reload(id)
		}

		if captcha.WriteImage(w, id, imgWidth, imgHeight) == captcha.ErrNotFound {
			http.NotFound(w, r)
			return
		}
		return
	}

	// check if action not required captcha check
	if !ca.captchaMatcher.Match(action) {
		next(w, r)
		return
	}

	// 判断是否要进行验证码检测
	isCaptchaRequiredAction := false
	if ca.captchaMatcher.Match(action) {
		isCaptchaRequiredAction = true

		// 检测启动条件
		needCaptcha := false
		captchaConfig := ca.captchaConfigs[action]
		if captchaConfig.maxFailCount == 0 {
			needCaptcha = true
		} else {
			// 检查是否超过最大失败次数
			idVal := r.Form.Get(captchaConfig.identifier)
			key := fmt.Sprintf("%s|%s", action, idVal)
			item, has := ca.captchaCache.Get(key)
			if has && item.MustInt(0) > captchaConfig.maxFailCount {
				needCaptcha = true
			}
		}

		if needCaptcha {
			id := r.Form.Get("CaptchaId")
			code := r.Form.Get("CaptchaCode")
			if id == "" || code == "" {
				api.WriteResponse(c, c.Error.NewGroupError("captcha", errorMissingCaptcha))
				return
			}
			if !captcha.VerifyString(id, code) {
				// 验证失败，刷新验证码
				captcha.Reload(id)
				api.WriteResponse(c, c.Error.NewGroupError("captcha", errorWrongCaptcha))
				return
			} else {
				// 验证成功，也一样刷新，防止重复利用
				captcha.Reload(id)
			}
		}
	}

	// next middleware
	next(w, r)

	// 操作失败次数计数，用于验证码开启检测
	if isCaptchaRequiredAction {
		captchaConfig := ca.captchaConfigs[action]
		if captchaConfig.maxFailCount > 0 {
			idVal := r.Form.Get(captchaConfig.identifier)
			key := fmt.Sprintf("%s|%s", action, idVal)
			data := c.Get("returnData")
			if api.IsError(data) {
				// 调用失败，计数加1
				item, has := ca.captchaCache.Get(key)
				if !has {
					ca.captchaCache.Set(key, 1)
				} else {
					ca.captchaCache.Set(key, item.MustInt(0)+1)
				}
			} else {
				// 调用成功，清空计数
				if ca.captchaCache.Has(key) {
					ca.captchaCache.Set(key, 0)
				}
			}
		}
	}
}
