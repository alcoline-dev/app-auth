<?php

namespace Alcoline\Auth\Api\DTO;

use Ufo\DTO\ArrayConstructibleTrait;
use Ufo\DTO\ArrayConvertibleTrait;
use Ufo\DTO\Interfaces\IArrayConstructible;
use Ufo\DTO\Interfaces\IArrayConvertible;

class UserMeInfoView implements IArrayConvertible, IArrayConstructible
{
    use ArrayConstructibleTrait, ArrayConvertibleTrait;

    /**
     * @param RoleDTO[] $roles
     */
    public function __construct(
        public string $userId,
        public string $phone,
        public string $fullName,
        public string $firstName,
        public string $lastName,
        public string $roleName,
        public string $roleSlug,
        public RoleDTO $mainRole,
        public array $roles,
        public string $createdAt,
        public string $updatedAt,
        public string|null $email = null,
        public string|null $externalId = null,
        public ?string $routeName = null,
        public ?RoleDTO $authorizedRole = null
    ) {}
}