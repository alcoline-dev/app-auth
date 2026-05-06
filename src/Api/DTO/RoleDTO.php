<?php

declare(strict_types = 1);

namespace Alcoline\Auth\Api\DTO;

use Ufo\DTO\ArrayConstructibleTrait;
use Ufo\DTO\ArrayConvertibleTrait;
use Ufo\DTO\Interfaces\IArrayConstructible;
use Ufo\DTO\Interfaces\IArrayConvertible;

class RoleDTO implements IArrayConstructible, IArrayConvertible
{
    use ArrayConstructibleTrait, ArrayConvertibleTrait;

    public function __construct(
        public string $slug,
        public string $name,
        public int $level = 0
    ) {}
}