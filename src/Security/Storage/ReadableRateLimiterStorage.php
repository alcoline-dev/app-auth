<?php

declare(strict_types=1);

namespace Alcoline\Auth\Security\Storage;

use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\RateLimiter\LimiterStateInterface;
use Symfony\Component\RateLimiter\Storage\StorageInterface;

class ReadableRateLimiterStorage implements StorageInterface
{
    public function __construct(
        protected CacheItemPoolInterface $pool,
        protected bool $hashingIp = false
    ) {}

    public function save(LimiterStateInterface $limiterState): void
    {
        $cacheItem = $this->pool->getItem($this->buildKey($limiterState->getId()));
        $cacheItem->set($limiterState);
        if (null !== ($expireAfter = $limiterState->getExpirationTime())) {
            $cacheItem->expiresAfter($expireAfter);
        }

        $this->pool->save($cacheItem);
    }

    public function fetch(string $limiterStateId): ?LimiterStateInterface
    {
        $cacheItem = $this->pool->getItem($this->buildKey($limiterStateId));
        $value = $cacheItem->get();
        if ($value instanceof LimiterStateInterface) {
            return $value;
        }

        return null;
    }

    public function delete(string $limiterStateId): void
    {
        $this->pool->deleteItem($this->buildKey($limiterStateId));
    }

    protected function buildKey(string $stateId): string
    {
        if (!str_contains($stateId, '-')) {
            return 'rate_limit.' . hash('sha256', $stateId);
        }

        [$limiterId, $ip] = explode('-', $stateId, 2);

        if ($limiterId === '' || $ip === '') {
            return 'rate_limit.' . hash('sha256', $stateId);
        }

        $safeLimiterId = str_replace([':', '-'], '_', $limiterId);
        $safeIp = $this->hashingIp ? sha1($ip) : str_replace([':', '-'], '_', $ip);

        return sprintf(
            'rate_limit.%s.%s',
            $safeLimiterId,
            $safeIp
        );
    }
}