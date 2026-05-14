<?php

declare(strict_types=1);

namespace Alcoline\Auth\Listeners;

use Alcoline\Auth\Exceptions\LoginRateLimitException;
use Alcoline\Auth\Security\Service\LoginLimiter;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Ufo\JsonRpcBundle\EventDrivenModel\Events\RpcErrorEvent;
use Ufo\JsonRpcBundle\EventDrivenModel\Events\RpcEvent;
use Ufo\JsonRpcBundle\EventDrivenModel\Events\RpcPostResponseEvent;
use Ufo\JsonRpcBundle\EventDrivenModel\Events\RpcPreExecuteEvent;

#[AsEventListener(event: RpcEvent::PRE_EXECUTE, method: 'checkIp', priority: 1000000)]
#[AsEventListener(event: RpcEvent::ERROR, method: 'incrementIp', priority: 100)]
#[AsEventListener(event: RpcEvent::POST_RESPONSE, method: 'resetIp', priority: 100)]
class IpListener
{
    public function __construct(
        protected LoginLimiter $loginLimiter,
        protected array $checkMethods = [],
    ) {}

    public function checkIp(RpcPreExecuteEvent $event): void
    {
        if (!$this->shouldCheck($event->rpcRequest->getMethod())) return;
        $this->loginLimiter->checkIp();
    }

    public function incrementIp(RpcErrorEvent $event): void
    {
        if ($this->shouldCheck($event->rpcRequest->getMethod()) && !$event->exception instanceof LoginRateLimitException) {
            $this->loginLimiter->incrementCurrentIp();
        }

        throw $event->exception;
    }

    public function resetIp(RpcPostResponseEvent $event): void
    {
        if (!$this->shouldCheck($event->rpcRequest->getMethod())) return;
        $this->loginLimiter->clearCurrentIp();
    }

    protected function shouldCheck(?string $method): bool
    {
        if (!$method) {
            return false;
        }

        foreach ($this->checkMethods as $pattern) {
            if (preg_match('#^' . $pattern . '$#', $method)) {
                return true;
            }
        }

        return false;
    }
}
