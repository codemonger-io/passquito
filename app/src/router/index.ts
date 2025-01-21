import { createRouter, createWebHistory } from 'vue-router'
import SignUp from '../views/SignUp.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
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
    }
  ]
})

export default router
