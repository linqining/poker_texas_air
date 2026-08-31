import axios from 'axios';
import { getToken } from './getToken';

const baseURL = '/api';

export const httpClient = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
});

httpClient.interceptors.request.use(
  (config) => {
    const token = getToken();
    if (token) {
      config.headers['x-auth-token'] = token;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// 会话过期统一广播：任何 API 返回 401（token 无效/过期）时派发事件，
// 由 useAuth 监听并清理前端登录态（避免服务端重启/过期后前端仍显示登录）。
httpClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error?.response?.status === 401) {
      window.dispatchEvent(new Event('zgame:session-expired'));
    }
    return Promise.reject(error);
  }
);

export default httpClient;
