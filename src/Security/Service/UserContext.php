<?php

declare(strict_types=1);

namespace Alcoline\Auth\Security\Service;

use Alcoline\Auth\Api\DTO\UserMeInfoView;

class UserContext
{
    private ?UserMeInfoView $user = null;

    public function addUser(UserMeInfoView $user): void
    {
        $this->user = $user;
    }

    public function getUser(): ?UserMeInfoView
    {
        return $this->user;
    }
}
