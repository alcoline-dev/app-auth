<?php

namespace Alcoline\Auth\Listeners;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Ufo\JsonRpcBundle\EventDrivenModel\Events\RpcErrorEvent;
use Ufo\JsonRpcBundle\EventDrivenModel\Events\RpcEvent;
use Ufo\RpcError\RpcInternalException;
use Ufo\RpcError\RpcInvalidTokenException;

#[AsEventListener(RpcEvent::ERROR, 'onRpcError')]
class InvalidTokenListener
{
    public function onRpcError(RpcErrorEvent $event): void
    {
        if ($event->rpcRequest->getMethod() === 'user.me' && $event->exception instanceof RpcInternalException) {
            throw new RpcInvalidTokenException($event->exception->getMessage());
        }
    }
}