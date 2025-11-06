<?php

namespace Alcoline\Auth\Contracts;

interface ISecuritySDK extends ICanPing
{
    public function can(string $permission, string $agent, array $context = []): bool;
}