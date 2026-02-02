<?php

declare(strict_types=1);

namespace Alcoline\Auth\Exceptions;

class LoginRateLimitException extends \DomainException
{
    protected $message = 'Too many login attempts. Please try again later.';
    protected $code = -32400;

    public static function fromIp(string $ip, int $code = -32400): static
    {
        return new static(sprintf(
            'Too many login attempts from IP "%s". Please try again later.',
            $ip
        ), code: $code);
    }
}