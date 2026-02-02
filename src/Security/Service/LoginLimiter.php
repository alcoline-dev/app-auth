<?php

declare(strict_types=1);

namespace Alcoline\Auth\Security\Service;

use Alcoline\Auth\Exceptions\LoginRateLimitException;
use Closure;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\RateLimiter\RateLimiterFactory;

final readonly class LoginLimiter
{
    public function __construct(
        private RateLimiterFactory $loginLimiter,
        private RequestStack $requestStack
    ) {}

    public function canLogin(string $key): bool
    {
        $limiter = $this->loginLimiter->create($key);
        return $limiter->consume(0)->getRemainingTokens() !== 0;
    }

    public function increment(string $key, int $tokens = 1): bool
    {
        $limiter = $this->loginLimiter->create($key);
        return $limiter->consume($tokens)->isAccepted();
    }

    public function clear(string $key): void
    {
        $limiter = $this->loginLimiter->create($key);
        $limiter->reset();
    }

    /**
     * @throws LoginRateLimitException
     */
    public function checkIp(): bool
    {
        return $this->handle(function (string $clientIp) {
            if (!$this->canLogin($clientIp)) {
                throw LoginRateLimitException::fromIp($clientIp);
            }
            return true;
        });
    }

    public function incrementCurrentIp(int $tokens = 1): bool
    {
        return $this->handle(function (string $clientIp) use ($tokens) {
            return $this->increment($clientIp, $tokens);
        });
    }

    public function clearCurrentIp(): bool
    {
        return $this->handle(function (string $clientIp) {
            $this->clear($clientIp);
            return true;
        });
    }

    protected function handle(Closure $callback): bool
    {
        $clientIp = $this->getMainRequest()?->getClientIp();
        if ($clientIp) {
            return $callback($clientIp);
        }
        return false;
    }

    public function getMainRequest(): ?Request
    {
        return $this->requestStack->getMainRequest();
    }
}
