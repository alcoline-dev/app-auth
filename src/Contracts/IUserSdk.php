<?php

declare(strict_types = 1);

namespace Alcoline\Auth\Contracts;

use Alcoline\Auth\Api\DTO\RoleDTO;

interface IUserSdk extends ICanPing
{

    public function getOTP(string $phone, string $appName, ?string $asRole = null): string;

    public function login(string $phone, string $otp, string $appName, ?string $asRole = null): object;

    public function refresh(string $refreshToken): object;

    public function me(string $accessToken): object;

    public function info(string $userId): object;

    public function getByData(string $user): object;

    public function getRole(string $user, ?string $roleSlug = null): RoleDTO;

    public function getAuthorizedRole(string $accessToken): RoleDTO;
}