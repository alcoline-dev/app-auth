<?php

declare(strict_types=1);

namespace Alcoline\Auth\Api;

use Alcoline\Auth\Api\DTO\UserMeInfoView;
use Alcoline\Auth\Contracts\IAsyncMessengerSDK;
use Alcoline\Auth\Contracts\IMessengerSDK;
use Alcoline\Auth\Contracts\IUserSdk;
use Alcoline\Auth\Exceptions\GetOTPException;
use Alcoline\Auth\Security\Service\LoginLimiter;
use Alcoline\Auth\Security\Service\UserContext;
use Symfony\Component\Validator\Constraints as Assert;
use Twig\Environment;
use Twig\Error\LoaderError;
use Twig\Error\RuntimeError;
use Twig\Error\SyntaxError;
use Ufo\DTO\DTOTransformer;
use Ufo\RpcError\RpcInvalidTokenException;
use Ufo\RpcObject\RPC;

class UserApi
{
    public const string OTP_SUBJECT = 'ОТР пароль';
    public const string TWIG_TEMPLATE = 'otp_message.html.twig';
    public const string SYSTEM_SENDER = 'system';

    public function __construct(
        protected IMessengerSDK $messengerSdkService,
        protected IAsyncMessengerSdk $messengerAsyncSdkService,
        protected IUserSdk $userSdkService,
        protected UserContext $userContext,
        protected Environment $twig,
        protected LoginLimiter $loginLimiter,
        protected string $otpTemplate = self::TWIG_TEMPLATE,
        protected string $otpSubject = self::OTP_SUBJECT,
        protected string $sender = self::SYSTEM_SENDER,
    ) {}

    /**
     * Отримання otp кода, та відправка його через мессенджер
     *
     * @param string $phone Номер телефону користувача
     * @return bool
     *
     * @throws LoaderError
     * @throws RuntimeError
     * @throws SyntaxError
     */
    public function getOTP(
        #[RPC\Assertions([
            new Assert\NotBlank,
            new Assert\Regex(
                pattern: '/^\+380\d{9}$/',
                message: 'The phone number is not a valid UA mobile number'
            ),
        ])] string $phone,
        #[RPC\Assertions([new Assert\NotBlank])]
        string $appName,
        ?string $asRole = null
    ): bool
    {
        try {
            $role = $this->userSdkService->getRole($phone, $asRole);
            $otp = $this->userSdkService->getOTP($phone, $appName, $role->slug);
        } catch (\Exception) {
            throw new GetOTPException();
        }

        $this->sendOtp($otp, $phone, $role->name);

        return true;
    }

    protected function sendOtp(string $otp, string $phone, string $role): void
    {
        $message = $this->twig->render($this->otpTemplate, ['otp' => $otp, 'role' => $role]);

        $this->messengerSdkService->send(
            message: $message,
            subject: $this->otpSubject,
            contactId: $phone,
            channel: IMessengerSDK::DEFAULT_CHANEL,
            sender: $this->sender,
        );
    }

    /**
     * Вхід, отримання доступу
     *
     * @param string $phone Номер телефону користувача
     * @param string $otp OTP Код
     * @return object повертає обʼєкт доступу з токенами
     *
     */
    public function login(
        #[RPC\Assertions([
            new Assert\NotBlank,
            new Assert\Regex(
                pattern: '/^\+380\d{9}$/',
                message: 'The phone number is not a valid UA mobile number'
            ),
        ])]
        string $phone,
        #[RPC\Assertions([new Assert\NotBlank])]
        string $otp,
        #[RPC\Assertions([new Assert\NotBlank])]
        string $appName,
        ?string $asRole = null
    ): object
    {
        return $this->userSdkService->login($phone, $otp, $appName, $asRole);
    }

    /**
     * Отримання інформації по користовачу
     *
     * @param string|null $accessToken Токен входу
     * @return UserMeInfoView повертає обʼєкт інфо
     * @throws RpcInvalidTokenException
     */
    public function me(
        #[RPC\Assertions([new Assert\Optional(), new Assert\Uuid])]
        ?string $accessToken = null
    ): UserMeInfoView
    {
        try {
            $user = $this->userContext->getUser() ?? $this->userSdkService->me($accessToken ?? '');
        } catch (\Throwable $e) {
            $this->loginLimiter->checkIp();
            throw new RpcInvalidTokenException($e->getMessage(), previous: $e);
        }
        $this->loginLimiter->clearCurrentIp();
        return UserMeInfoView::fromArray(DTOTransformer::toArray($user));
    }

    /**
     * Оновлення доступу
     *
     * @param string $refreshToken Рефреш токен
     * @return object повертає оновленний обʼєкт входу
     */
    public function refresh(
        #[RPC\Assertions([new Assert\NotBlank, new Assert\Uuid])] string $refreshToken
    ): object
    {
        return $this->userSdkService->refresh($refreshToken);
    }
}
