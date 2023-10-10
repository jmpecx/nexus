<?php

namespace App\Auth;

use App\Models\User;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

class MyUserProvider extends EloquentUserProvider
{
    //

    /**
     * Validate a user against the given credentials.
     * 覆盖原有逻辑以实现：
     * 自定义的密码校验
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @param array $credentials
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        // 如果提交的内容中不含 password，那就bye bye,
        // 下一个更乖
        if (is_null($plain = $credentials['password'])) {
            return false;
        }
        // hash对比，两者
        //  md5($row["secret"] . $password . $row["secret"])
        return $this->hasher->check($user['secret'] . $plain . $user['secret'], $user->getAuthPassword());
    }
}
