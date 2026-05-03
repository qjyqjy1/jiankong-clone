/**
 * 小猪智能体面板 - 认证模块
 * 关键操作使用服务端会话校验，浏览器端不保存明文密码。
 */
(function() {
    'use strict';

    const AUTH_CONFIG = {
        username: 'qjyqjy',
        sessionKey: 'nexus_auth',
        sessionTTL: 24 * 60 * 60 * 1000
    };

    function readLocalAuth() {
        try {
            const auth = sessionStorage.getItem(AUTH_CONFIG.sessionKey);
            if (!auth) return null;
            const data = JSON.parse(auth);
            if (!data || !data.authenticated || !data.timestamp) return null;
            if (Date.now() - data.timestamp > AUTH_CONFIG.sessionTTL) {
                sessionStorage.removeItem(AUTH_CONFIG.sessionKey);
                return null;
            }
            return data;
        } catch (e) {
            return null;
        }
    }

    function isAuthenticated() {
        return !!readLocalAuth();
    }

    function markAuthenticated() {
        sessionStorage.setItem(AUTH_CONFIG.sessionKey, JSON.stringify({
            authenticated: true,
            timestamp: Date.now()
        }));
    }

    function clearAuthenticated() {
        sessionStorage.removeItem(AUTH_CONFIG.sessionKey);
    }

    async function checkServerAuth() {
        try {
            const resp = await fetch('/api/auth/status', { cache: 'no-store' });
            const data = await resp.json();
            if (!data.authenticated) clearAuthenticated();
            return !!data.authenticated;
        } catch (e) {
            clearAuthenticated();
            return false;
        }
    }

    function showAuthModal(onSuccess, onCancel) {
        const overlay = document.createElement('div');
        overlay.id = 'auth-overlay';
        overlay.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.72);backdrop-filter:blur(8px);z-index:9999;display:flex;align-items:center;justify-content:center;animation:fadeIn 0.2s ease;padding:16px;';

        const modal = document.createElement('div');
        modal.style.cssText = 'background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:28px;width:100%;max-width:380px;box-shadow:0 24px 80px rgba(0,0,0,0.5);animation:modalIn 0.3s cubic-bezier(0.16,1,0.3,1);';

        modal.innerHTML = `
            <div style="text-align:center;margin-bottom:20px;">
                <div style="width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,var(--accent-1),var(--accent-2));display:flex;align-items:center;justify-content:center;margin:0 auto 12px;">
                    <i class="fas fa-lock" style="color:white;font-size:20px;"></i>
                </div>
                <h3 style="font-size:18px;font-weight:700;color:var(--text-primary);">身份认证</h3>
                <p style="font-size:13px;color:var(--text-muted);margin-top:4px;">此操作需要验证身份</p>
            </div>
            <div style="margin-bottom:16px;">
                <input type="text" id="auth-username" placeholder="用户名" autocomplete="username" value="${AUTH_CONFIG.username}" style="width:100%;padding:10px 14px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:14px;outline:none;margin-bottom:10px;box-sizing:border-box;">
                <input type="password" id="auth-password" placeholder="密码" autocomplete="current-password" style="width:100%;padding:10px 14px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-size:14px;outline:none;box-sizing:border-box;">
            </div>
            <div id="auth-error" style="color:var(--accent-6);font-size:12px;margin-bottom:12px;text-align:center;display:none;"></div>
            <div style="display:flex;gap:8px;">
                <button id="auth-cancel" style="flex:1;padding:10px;border:1px solid var(--border);border-radius:8px;background:transparent;color:var(--text-muted);font-size:14px;cursor:pointer;">取消</button>
                <button id="auth-submit" style="flex:1;padding:10px;border:none;border-radius:8px;background:linear-gradient(135deg,var(--accent-1),var(--accent-2));color:white;font-size:14px;font-weight:600;cursor:pointer;">确认</button>
            </div>
        `;

        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        if (!document.getElementById('auth-styles')) {
            const style = document.createElement('style');
            style.id = 'auth-styles';
            style.textContent = `
                @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                @keyframes modalIn { from { opacity: 0; transform: translateY(20px) scale(0.97); } to { opacity: 1; transform: translateY(0) scale(1); } }
                #auth-username:focus, #auth-password:focus { border-color: var(--accent-2); background: rgba(255,255,255,0.06); }
            `;
            document.head.appendChild(style);
        }

        const usernameEl = document.getElementById('auth-username');
        const passwordEl = document.getElementById('auth-password');
        const errorEl = document.getElementById('auth-error');
        const submitEl = document.getElementById('auth-submit');

        setTimeout(() => passwordEl.focus(), 100);

        function closeModal(cancelled) {
            overlay.remove();
            if (cancelled && onCancel) onCancel();
        }

        async function doAuth() {
            const username = usernameEl.value.trim();
            const password = passwordEl.value;
            if (!username || !password) {
                errorEl.textContent = '请输入用户名和密码';
                errorEl.style.display = 'block';
                return;
            }

            submitEl.disabled = true;
            submitEl.textContent = '验证中...';
            errorEl.style.display = 'none';

            try {
                const resp = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await resp.json();
                if (resp.ok && data.success) {
                    markAuthenticated();
                    closeModal(false);
                    if (onSuccess) onSuccess();
                    return;
                }
                errorEl.textContent = data.error || '认证失败';
            } catch (e) {
                errorEl.textContent = '认证请求失败：' + e.message;
            } finally {
                submitEl.disabled = false;
                submitEl.textContent = '确认';
                passwordEl.value = '';
                passwordEl.focus();
                errorEl.style.display = 'block';
            }
        }

        passwordEl.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') doAuth();
        });
        usernameEl.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') passwordEl.focus();
        });
        overlay.addEventListener('click', function(e) {
            if (e.target === overlay) closeModal(true);
        });
        document.getElementById('auth-submit').addEventListener('click', doAuth);
        document.getElementById('auth-cancel').addEventListener('click', function() { closeModal(true); });
    }

    window.requireAuth = async function(onSuccess, onCancel) {
        if (isAuthenticated() && await checkServerAuth()) {
            if (onSuccess) onSuccess();
            return;
        }
        showAuthModal(onSuccess, onCancel);
    };

    window.isAuthenticated = isAuthenticated;
    window.NexusAuth = {
        requireAuth: window.requireAuth,
        isAuthenticated: window.isAuthenticated
    };
})();
