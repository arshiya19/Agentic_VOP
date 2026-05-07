import { createContext, useContext, useEffect, useState, useRef } from 'react'
import { supabase } from '../lib/supabase'

const AuthContext = createContext({})

// Dev-only bypass: set VITE_BYPASS_AUTH=true in .env.local to skip Supabase auth
// during local development. Hardcoded to false in production builds.
const BYPASS_AUTH =
  import.meta.env.DEV && import.meta.env.VITE_BYPASS_AUTH === 'true'

// eslint-disable-next-line react-refresh/only-export-components
export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [userRole, setUserRole] = useState(null)
  const [loading, setLoading] = useState(true)
  const [lastRefresh, setLastRefresh] = useState(Date.now())
  const lastFetchRef = useRef(0)

  useEffect(() => {
    if (BYPASS_AUTH) return
    let mounted = true

    const initializeAuth = async () => {
      if (!mounted) return

      try {
        const { data: { session } } = await supabase.auth.getSession()

        if (!mounted) return

        if (session?.user) {
          setUser(session.user)
          await fetchUserRole(session.user.id)
        } else {
          setUser(null)
          setLoading(false)
        }
      } catch {
        if (mounted) {
          setUser(null)
          setLoading(false)
        }
      }
    }

    initializeAuth()

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange(async (event, session) => {
      if (event === 'SIGNED_IN' && session?.user) {
        setUser(session.user)

        const role = await fetchUserRole(session.user.id)

        const currentPath = window.location.pathname
        if (currentPath === '/login' || currentPath === '/signup' || currentPath === '/') {
          setTimeout(() => {
            if (role === 'admin') {
              window.location.href = '/admin/dashboard'
            } else {
              window.location.href = '/dashboard'
            }
          }, 100)
        }
      } else if (event === 'SIGNED_OUT') {
        setUser(null)
        setUserRole(null)
        setLoading(false)
      } else if (event === 'TOKEN_REFRESHED') {
        setUser(session?.user ?? null)
      } else if (event === 'USER_UPDATED') {
        setUser(session?.user ?? null)
      } else {
        setUser(session?.user ?? null)
        if (!session?.user) {
          setUserRole(null)
          setLoading(false)
        }
      }
    })

    return () => {
      mounted = false
      subscription.unsubscribe()
    }
  }, [])

  const debouncedRefreshSession = () => {
    const now = Date.now()
    const timeSinceLastRefresh = now - lastRefresh

    if (timeSinceLastRefresh > 5000) {
      setLastRefresh(now)
      refreshSession()
    }
  }

  const refreshSession = async () => {
    if (!user) return

    try {
      const { data: { session }, error } = await supabase.auth.getSession()

      if (error) {
        setUser(null)
        setUserRole(null)
        return
      }

      if (session?.user) {
        setUser(session.user)
        await fetchUserRole(session.user.id)
      } else {
        setUser(null)
        setUserRole(null)
      }
    } catch {
      setUser(null)
      setUserRole(null)
    }
  }

  useEffect(() => {
    if (BYPASS_AUTH) return
    const handleFocus = () => {
      debouncedRefreshSession()
    }

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        debouncedRefreshSession()
      }
    }

    const handlePageShow = (event) => {
      if (event.persisted) {
        debouncedRefreshSession()
      }
    }

    window.addEventListener('focus', handleFocus)
    document.addEventListener('visibilitychange', handleVisibilityChange)
    window.addEventListener('pageshow', handlePageShow)

    return () => {
      window.removeEventListener('focus', handleFocus)
      document.removeEventListener('visibilitychange', handleVisibilityChange)
      document.removeEventListener('pageshow', handlePageShow)
    }
  }, [user, lastRefresh])

  const fetchUserRole = async (userId) => {
    const now = Date.now()
    if (now - lastFetchRef.current < 2000) {
      return userRole || 'user'
    }
    lastFetchRef.current = now

    try {
      const timeoutPromise = new Promise((resolve) =>
        setTimeout(() => {
          resolve({ data: { role: 'user' }, error: null })
        }, 5000)
      )

      const result = await Promise.race([
        supabase
          .from('users')
          .select('role')
          .eq('id', userId)
          .single(),
        timeoutPromise,
      ])

      const { data, error } = result

      if (error && error.message !== 'fetchUserRole timeout') throw error

      const role = data?.role || 'user'
      setUserRole(role)
      setLoading(false)
      return role
    } catch {
      setUserRole('user')
      setLoading(false)
      return 'user'
    }
  }

  const signUp = async (email, password, selectedRole = 'user') => {
    try {
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
      })

      if (error) throw error

      if (data.user) {
        await supabase
          .from('users')
          .upsert(
            {
              id: data.user.id,
              email,
              role: selectedRole === 'admin' ? 'admin' : 'user',
            },
            { onConflict: 'id' }
          )
      }

      return { data, error: null }
    } catch (error) {
      return { data: null, error }
    }
  }

  const signIn = async (email, password) => {
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
      })

      if (error) throw error

      return { data, error: null }
    } catch (error) {
      return { data: null, error }
    }
  }

  const signOut = async () => {
    // Best-effort Supabase signout; we still clear local state below regardless.
    await supabase.auth.signOut({ scope: 'global' }).catch(() => {})

    localStorage.clear()
    sessionStorage.clear()

    document.cookie.split(';').forEach((c) => {
      document.cookie = c
        .replace(/^ +/, '')
        .replace(/=.*/, '=;expires=' + new Date().toUTCString() + ';path=/')
    })

    setUser(null)
    setUserRole(null)

    window.location.href = '/login'
  }

  if (BYPASS_AUTH) {
    if (typeof window !== 'undefined') {
      const path = window.location.pathname
      if (path === '/' || path === '/login' || path === '/signup') {
        window.location.replace('/admin/dashboard')
      }
    }
    const bypassValue = {
      user: { id: 'dev-user', email: 'dev@local' },
      userRole: 'admin',
      loading: false,
      signUp: async () => {
        window.location.href = '/admin/dashboard'
        return { data: null, error: null }
      },
      signIn: async () => {
        window.location.href = '/admin/dashboard'
        return { data: null, error: null }
      },
      signOut: async () => {
        window.location.href = '/login'
      },
    }
    return <AuthContext.Provider value={bypassValue}>{children}</AuthContext.Provider>
  }

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner">
          <div></div>
          Loading...
        </div>
      </div>
    )
  }

  const value = {
    user,
    userRole,
    loading,
    signUp,
    signIn,
    signOut,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
