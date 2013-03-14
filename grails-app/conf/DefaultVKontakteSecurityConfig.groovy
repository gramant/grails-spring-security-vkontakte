security {

	vkontakte {

        appId = "Invalid"
        secret = 'Invalid'
        apiKey = 'Invalid'

        domain {
            classname = 'VKontakteUser'
            connectionPropertyName = "user"
        }

        useAjax = true
        autoCheck = true

        jsconf = "vkSecurity"

        permissions = [""]

        taglib {
            language = "en_US"
            button {
                text = "Login with VKontakte"
            }
            initvk = true
            //see http://vk.com/developers.php?oid=-1&p=%D0%9F%D1%80%D0%B0%D0%B2%D0%B0_%D0%B4%D0%BE%D1%81%D1%82%D1%83%D0%BF%D0%B0_%D0%BF%D1%80%D0%B8%D0%BB%D0%BE%D0%B6%D0%B5%D0%BD%D0%B8%D0%B9
            permissions = [""]
        }

        autoCreate {
            active = true
            roleNames = ['ROLE_USER', 'ROLE_VKONTAKTE']
        }

        filter {
            processUrl = "/j_spring_vk_security_check"
            redirectFromUrl = "/j_spring_security_vk_redirect"
            type = 'redirect' //transparent, cookieDirect or redirect
            position = 730 //see SecurityFilterPosition
            forceLoginParameter = 'j_spring_vk_force'
        }

        beans {
        }

    }
}