<?php

declare(strict_types = 1);

namespace Alcoline\Auth\Api\DTO;

class RoleDTO
{
    public function __construct(
        public string $slug,
        public string $name
    ) {}
}