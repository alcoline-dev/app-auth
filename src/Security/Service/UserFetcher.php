<?php

declare(strict_types=1);

namespace Alcoline\Auth\Security\Service;

use Alcoline\Auth\Api\DTO\UserMeInfoView;
use Alcoline\Auth\Contracts\IUserSdk;
use Ufo\DTO\DTOTransformer;

readonly class UserFetcher
{
    public function __construct(
        private IUserSdk $userProcedure
    ) {}

    public function getUserFromAccessToken(string $accessToken): UserMeInfoView
    {
        $user = $this->userProcedure->me($accessToken);
        return UserMeInfoView::fromArray(DTOTransformer::toArray($user));
    }
}
