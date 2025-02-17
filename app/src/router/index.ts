import { createRouter, createWebHistory } from 'vue-router'
import SignUp from '../views/SignUp.vue'

const router = createRouter({
  history: createWebHistory(
    // as BASE_URL may be a full URL, we extracts only the path part of it.
    // the second argument of the URL constructor is provided so that non-URL
    // BASE_URL can be correctly parsed.
    new URL(import.meta.env.BASE_URL, 'https://codemonger.io').pathname
  ),
  routes: [
    {
      path: '/',
      name: 'home',
      component: SignUp,
      props: (route) => ({
        message: route.query.message
      })
    },
    {
      path: '/signin',
      name: 'signin',
      component: () => import('../views/SignIn.vue')
    },
    {
      path: '/signin-dummy',
      name: 'signin-dummy',
      component: () => import('../views/SignInDummy.vue')
    },
    {
      path: '/secured',
      name: 'secured',
      component: () => import('../views/Secured.vue')
    },
    {
      path: '/invite-device',
      name: 'invite-device',
      component: () => import('../views/InviteDevice.vue')
    },
    {
      path: '/register-device/:sessionId',
      name: 'register-device',
      component: () => import('../views/RegisterDevice.vue'),
      props: true
    }
  ]
})

export default router
