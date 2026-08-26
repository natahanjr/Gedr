import React, { createContext, useState, useContext } from 'react';
import { useRouter } from 'next/router';
import api from '../lib/api';

const AuthContext = createContext({});

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const router = useRouter();

  const login = async (username, password) => {
    try {
      const res = await api.post('/api/auth/login', {
        username,
        password,
      });
      const { access_token, role } = res.data;
      localStorage.setItem('auth_token', access_token);
      setUser({ username, role });
      router.push('/dashboard');
    } catch (e) {
      throw new Error('Invalid credentials');
    }
  };

  const logout = () => {
    localStorage.removeItem('auth_token');
    setUser(null);
    router.push('/login');
  };

  return (
    <AuthContext.Provider value={{ user, setUser, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
