// 错误定义

package apicaptcha

import (
	"github.com/go-apibox/api"
)

// error type
const (
	errorMissingCaptcha = iota
	errorWrongCaptcha
)

var ErrorDefines = map[api.ErrorType]*api.ErrorDefine{
	errorMissingCaptcha: api.NewErrorDefine(
		"MissingCaptcha",
		[]int{0},
		map[string]map[int]string{
			"en_us": {
				0: "Missing captcha!",
			},
			"zh_cn": {
				0: "缺少验证码！",
			},
		},
	),
	errorWrongCaptcha: api.NewErrorDefine(
		"WrongCaptcha",
		[]int{0},
		map[string]map[int]string{
			"en_us": {
				0: "Wrong captcha!",
			},
			"zh_cn": {
				0: "验证码错误！",
			},
		},
	),
}
