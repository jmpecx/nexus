<?php

namespace App\Auth\Hashing;

use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Hashing\AbstractHasher;

class Md5Hasher extends AbstractHasher implements HasherContract
{
    public function make($value, array $options = [])
    {
        return md5($value);
    }

    public function needsRehash($hashedValue, array $options = [])
    {
        return false;
    }

        /**
     * Check the given plain value against a hash.
     *
     * @param  string  $value
     * @param  string|null  $hashedValue
     * @param  array  $options
     * @return bool
     */
    public function check($value, $hashedValue, array $options = [])
    {
        if (is_null($hashedValue) || strlen($hashedValue) === 0) {
            return false;
        }

        return $this->make($value, $options) === $hashedValue;
    }
}
