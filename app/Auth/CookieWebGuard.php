<?php

namespace App\Auth;

use Carbon\Carbon;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;

class CookieWebGuard extends SessionGuard
{

    /**
     * Log a user into the application.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @param bool $remember
     * @return void
     */
    public function login(AuthenticatableContract $user, $remember = false)
    {
        // 写入session，方便直接登录
        // 后续的流程中，如果session存在，就不再需要cookie都行
        $this->updateSession($user->getAuthIdentifier());

        // 如果记住登录，我们需要写入cookie，方便后续使用
        if ($remember) {
            // todo: 写入cookie
//            $this->ensureRememberTokenIsSet($user);
//
//            $this->queueRecallerCookie($user);
            $passh = md5($user['passhash']);
            logincookie($user["id"], $passh, 0, get_setting('system.cookie_valid_days', 365) * 86400, true, true, true);
        }

        // If we have an event dispatcher instance set we will fire an event so that
        // any listeners will hook into the authentication events and run actions
        // based on the login and logout events fired from the guard instances.
        $this->fireLoginEvent($user, $remember);

        $this->setUser($user);
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if ($this->loggedOut) {
            return;
        }

        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (!is_null($this->user)) {
            return $this->user;
        }

        $id = $this->session->get($this->getName());

        // First we will try to load the user using the identifier in the session if
        // one exists. Otherwise we will check for a "remember me" cookie in this
        // request, and if one exists, attempt to retrieve the user using that.
        if (!is_null($id) && $this->user = $this->provider->retrieveById($id)) {
            $this->fireAuthenticatedEvent($this->user);
        }
        // 尝试从nexus php的cookie里获取， 如果获取成功还倒罢了，不然就走原来的逻辑
        if (is_null($this->user)) {
            $credentials = $this->request->cookie();
            $this->validateCookies($credentials);
        }


        // If the user is null, but we decrypt a "recaller" cookie we can attempt to
        // pull the user data on that cookie which serves as a remember cookie on
        // the application. Once we have a user we can return it to the caller.
        if (is_null($this->user) && !is_null($recaller = $this->recaller())) {
            $this->user = $this->userFromRecaller($recaller);

            if ($this->user) {
                $this->updateSession($this->user->getAuthIdentifier());

                $this->fireLoginEvent($this->user, true);
            }
        }

        return $this->user;
    }


    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @return bool
     */
    private function validateCookies(array $credentials = [])
    {
        $required = ['c_secure_pass', 'c_secure_uid', 'c_secure_login'];
        foreach ($required as $value) {
            if (empty($credentials[$value])) {
                return false;
            }
        }
        $b_id = base64($credentials["c_secure_uid"], false);
        $id = intval($b_id ?? 0);
        if (!$id || !is_valid_id($id) || strlen($credentials["c_secure_pass"]) != 32) {
            return false;
        }
        // 尝试从数据中获取id.
        $user = $this->provider->retrieveById($id);
        if ($user) {
            if ($credentials["c_secure_login"] == base64("yeah")) {
                /**
                 * Not IP related
                 * @since 1.8.0
                 */
                if ($credentials["c_secure_pass"] != md5($user->passhash)) {
                    return false;
                }
            } else {
                if ($credentials["c_secure_pass"] !== md5($user->passhash)) {
                    return false;
                }
            }
            $this->user = $user;
            return true;
        }
        return false;
    }

    /**
     * Remove the user data from the session and cookies.
     *
     * @return void
     */
    protected function clearUserDataFromStorage()
    {
        logoutcookie();
        try {
            parent::clearUserDataFromStorage();
        } catch (\Exception $exception) {
            // ignore.
        }
    }
}
