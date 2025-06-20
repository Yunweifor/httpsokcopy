// 通用JavaScript函数库
// 用于httpsok系统前端页面

// API基础URL
const API_BASE_URL = '/api/v1';

// 通用API请求函数
async function apiRequest(endpoint, method = 'GET', data = null, token = null) {
    const headers = {
        'Content-Type': 'application/json'
    };
    
    // 如果有token，添加到请求头
    if (token || localStorage.getItem('auth_token')) {
        headers['Authorization'] = `Bearer ${token || localStorage.getItem('auth_token')}`;
    }
    
    const options = {
        method,
        headers
    };
    
    if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
        
        // 处理401未授权错误，重定向到登录页
        if (response.status === 401) {
            localStorage.removeItem('auth_token');
            window.location.href = '/login.html';
            return null;
        }
        
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.message || '请求失败');
        }
        
        return result;
    } catch (error) {
        console.error('API请求错误:', error);
        showToast('错误', error.message || '网络请求失败', 'danger');
        return null;
    }
}

// 显示提示消息
function showToast(title, message, type = 'info') {
    // 创建toast元素
    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center text-white bg-${type} border-0`;
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');
    
    const toastContent = `
        <div class="d-flex">
            <div class="toast-body">
                <strong>${title}</strong>: ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    toastEl.innerHTML = toastContent;
    
    // 添加到toast容器
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    toastContainer.appendChild(toastEl);
    
    // 初始化并显示toast
    const toast = new bootstrap.Toast(toastEl, {
        delay: 5000
    });
    toast.show();
    
    // 自动移除
    toastEl.addEventListener('hidden.bs.toast', () => {
        toastEl.remove();
    });
}

// 格式化日期时间
function formatDateTime(dateString) {
    if (!dateString) return '-';
    
    const date = new Date(dateString);
    return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// 格式化日期
function formatDate(dateString) {
    if (!dateString) return '-';
    
    const date = new Date(dateString);
    return date.toLocaleDateString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    });
}

// 计算剩余天数
function calculateRemainingDays(expiryDate) {
    if (!expiryDate) return 0;
    
    const expiry = new Date(expiryDate);
    const today = new Date();
    
    // 设置时间为00:00:00以便准确计算天数
    today.setHours(0, 0, 0, 0);
    expiry.setHours(0, 0, 0, 0);
    
    const diffTime = expiry - today;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    return diffDays;
}

// 获取状态标签样式
function getStatusBadge(status, days = null) {
    let badgeClass = '';
    let statusText = status;
    
    switch (status.toLowerCase()) {
        case 'valid':
        case 'active':
        case 'normal':
        case '正常':
            badgeClass = 'bg-success';
            statusText = '正常';
            break;
        case 'pending':
        case 'processing':
        case '处理中':
            badgeClass = 'bg-info';
            statusText = '处理中';
            break;
        case 'warning':
        case '警告':
            badgeClass = 'bg-warning text-dark';
            statusText = '警告';
            break;
        case 'expired':
        case 'error':
        case 'failed':
        case '失败':
        case '过期':
            badgeClass = 'bg-danger';
            statusText = status.toLowerCase() === 'expired' ? '已过期' : '失败';
            break;
        default:
            badgeClass = 'bg-secondary';
    }
    
    // 如果提供了天数，根据天数调整状态
    if (days !== null && status.toLowerCase() === 'valid') {
        if (days <= 7) {
            badgeClass = 'bg-danger';
            statusText = '即将过期';
        } else if (days <= 30) {
            badgeClass = 'bg-warning text-dark';
            statusText = '警告';
        }
    }
    
    return `<span class="badge ${badgeClass}">${statusText}</span>`;
}

// 创建分页组件
function createPagination(currentPage, totalPages, onPageChange) {
    const paginationEl = document.getElementById('pagination');
    if (!paginationEl) return;
    
    paginationEl.innerHTML = '';
    
    // 上一页按钮
    const prevLi = document.createElement('li');
    prevLi.className = `page-item ${currentPage === 1 ? 'disabled' : ''}`;
    const prevLink = document.createElement('a');
    prevLink.className = 'page-link';
    prevLink.href = '#';
    prevLink.setAttribute('aria-label', '上一页');
    prevLink.innerHTML = '<span aria-hidden="true">&laquo;</span>';
    prevLi.appendChild(prevLink);
    paginationEl.appendChild(prevLi);
    
    // 页码按钮
    const maxVisiblePages = 5;
    let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
    let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
    
    if (endPage - startPage + 1 < maxVisiblePages) {
        startPage = Math.max(1, endPage - maxVisiblePages + 1);
    }
    
    // 第一页按钮
    if (startPage > 1) {
        const firstLi = document.createElement('li');
        firstLi.className = 'page-item';
        const firstLink = document.createElement('a');
        firstLink.className = 'page-link';
        firstLink.href = '#';
        firstLink.textContent = '1';
        firstLi.appendChild(firstLink);
        paginationEl.appendChild(firstLi);
        
        firstLink.addEventListener('click', (e) => {
            e.preventDefault();
            onPageChange(1);
        });
        
        // 省略号
        if (startPage > 2) {
            const ellipsisLi = document.createElement('li');
            ellipsisLi.className = 'page-item disabled';
            const ellipsisSpan = document.createElement('span');
            ellipsisSpan.className = 'page-link';
            ellipsisSpan.innerHTML = '&hellip;';
            ellipsisLi.appendChild(ellipsisSpan);
            paginationEl.appendChild(ellipsisLi);
        }
    }
    
    // 页码
    for (let i = startPage; i <= endPage; i++) {
        const pageLi = document.createElement('li');
        pageLi.className = `page-item ${i === currentPage ? 'active' : ''}`;
        const pageLink = document.createElement('a');
        pageLink.className = 'page-link';
        pageLink.href = '#';
        pageLink.textContent = i;
        pageLi.appendChild(pageLink);
        paginationEl.appendChild(pageLi);
        
        if (i !== currentPage) {
            pageLink.addEventListener('click', (e) => {
                e.preventDefault();
                onPageChange(i);
            });
        }
    }
    
    // 最后一页按钮
    if (endPage < totalPages) {
        // 省略号
        if (endPage < totalPages - 1) {
            const ellipsisLi = document.createElement('li');
            ellipsisLi.className = 'page-item disabled';
            const ellipsisSpan = document.createElement('span');
            ellipsisSpan.className = 'page-link';
            ellipsisSpan.innerHTML = '&hellip;';
            ellipsisLi.appendChild(ellipsisSpan);
            paginationEl.appendChild(ellipsisLi);
        }
        
        const lastLi = document.createElement('li');
        lastLi.className = 'page-item';
        const lastLink = document.createElement('a');
        lastLink.className = 'page-link';
        lastLink.href = '#';
        lastLink.textContent = totalPages;
        lastLi.appendChild(lastLink);
        paginationEl.appendChild(lastLi);
        
        lastLink.addEventListener('click', (e) => {
            e.preventDefault();
            onPageChange(totalPages);
        });
    }
    
    // 下一页按钮
    const nextLi = document.createElement('li');
    nextLi.className = `page-item ${currentPage === totalPages ? 'disabled' : ''}`;
    const nextLink = document.createElement('a');
    nextLink.className = 'page-link';
    nextLink.href = '#';
    nextLink.setAttribute('aria-label', '下一页');
    nextLink.innerHTML = '<span aria-hidden="true">&raquo;</span>';
    nextLi.appendChild(nextLink);
    paginationEl.appendChild(nextLi);
    
    // 添加事件监听
    if (currentPage > 1) {
        prevLink.addEventListener('click', (e) => {
            e.preventDefault();
            onPageChange(currentPage - 1);
        });
    }
    
    if (currentPage < totalPages) {
        nextLink.addEventListener('click', (e) => {
            e.preventDefault();
            onPageChange(currentPage + 1);
        });
    }
}

// 检查用户登录状态
function checkAuth() {
    const token = localStorage.getItem('auth_token');
    if (!token) {
        window.location.href = '/login.html';
        return false;
    }
    return true;
}

// 页面加载时执行
document.addEventListener('DOMContentLoaded', () => {
    // 检查当前页面是否需要登录
    if (window.location.pathname !== '/login.html' && 
        window.location.pathname !== '/register.html' && 
        window.location.pathname !== '/forgot-password.html') {
        checkAuth();
    }
    
    // 设置用户信息
    const userInfo = JSON.parse(localStorage.getItem('user_info') || '{}');
    const userNameEl = document.getElementById('userName');
    if (userNameEl && userInfo.username) {
        userNameEl.textContent = userInfo.username;
    }
    
    // 退出登录按钮
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user_info');
            window.location.href = '/login.html';
        });
    }
});
