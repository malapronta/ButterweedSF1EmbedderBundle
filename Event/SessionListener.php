<?php

namespace Butterweed\SF1EmbedderBundle\Event;

use Symfony\Component\DependencyInjection\ContainerAwareInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Butterweed\SF1EmbedderBundle\User\GuardUserInterface;

class SessionListener implements ContainerAwareInterface
{
    protected $container;
    protected $sessionAll;

    public function setContainer(ContainerInterface $container = null)
    {
        $this->container = $container;
    }

    public function onPreContext()
    {
        $session = $this->container->get('session');
        if ($session->isStarted()) {
            $session->save();
        }
        $this->sessionAll = $this->container->get('session')->all();

        // Remove Symfony 1 data from security (?? What does this mean?)
        foreach ($this->sessionAll as $key => $value) {
            if ('_' === substr($key, 0, 1)) {
                unset($this->sessionAll[$key]);
            }
        }
    }

    public function onPreDispatch(ContextEvent $event)
    {
        $context = $this->container->get('security.context');
        $session = $this->container->get('session');

        $sfUser = $event->getContext()->getUser();
        if ($context->getToken()) {
            $user = $context->getToken()->getUser();
            if ($sfUser instanceof \sfGuardSecurityUser && $user instanceof GuardUserInterface) {
                if ($context->isGranted('IS_AUTHENTICATED_FULLY')) {
                    if ($sfUser->isAuthenticated()) {
                        if (!$user->equalsGuard($sfUser)) {
                            $sfUser->signOut();
                            $sfUser->setSessionSf2($this->sessionAll);
                            $sfUser->signIn($user->getGuardUser());
                        }
                    } else {
                        $sfUser->setSessionSf2($this->sessionAll);
                        $sfUser->signIn($user->getGuardUser());
                    }
                } else {
                    $sfUser->signOut();
                }
            }
        }
    }

    public function onPostDispatch(ContextEvent $event)
    {
        $event->getContext()->getUser()->shutdown();
    }
}
