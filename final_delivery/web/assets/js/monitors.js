// 证书监控页面的JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // 检查用户登录状态
    if (!checkAuth()) return;
    
    // 初始化页面
    initMonitorsPage();
    
    // 绑定事件
    bindEvents();
});

// 初始化证书监控页面
async function initMonitorsPage() {
    // 加载监控列表
    await loadMonitors();
}

// 加载监控列表
async function loadMonitors(page = 1, limit = 10, search = '', sortBy = '') {
    try {
        // 显示加载中状态
        document.getElementById('monitorList').innerHTML = '<tr><td colspan="11" class="text-center">加载中...</td></tr>';
        
        // 构建查询参数
        const queryParams = new URLSearchParams({
            page: page,
            limit: limit
        });
        
        if (search) {
            queryParams.append('search', search);
        }
        
        if (sortBy) {
            queryParams.append('sort', sortBy);
        }
        
        // 调用API获取监控列表
        const response = await apiRequest(`/monitors?${queryParams.toString()}`);
        
        if (!response || !response.data) {
            document.getElementById('monitorList').innerHTML = '<tr><td colspan="11" class="text-center">加载失败，请重试</td></tr>';
            return;
        }
        
        const { monitors, total, totalPages } = response.data;
        
        // 渲染监控列表
        renderMonitorList(monitors);
        
        // 创建分页
        createPagination(page, totalPages, (newPage) => {
            loadMonitors(newPage, limit, search, sortBy);
        });
        
    } catch (error) {
        console.error('加载监控列表失败:', error);
        document.getElementById('monitorList').innerHTML = '<tr><td colspan="11" class="text-center">加载失败，请重试</td></tr>';
    }
}

// 渲染监控列表
function renderMonitorList(monitors) {
    const monitorListEl = document.getElementById('monitorList');
    
    if (!monitors || monitors.length === 0) {
        monitorListEl.innerHTML = '<tr><td colspan="11" class="text-center">暂无监控数据</td></tr>';
        return;
    }
    
    let html = '';
    
    monitors.forEach(monitor => {
        html += `
            <tr data-id="${monitor.id}">
                <td>${monitor.host || '-'}</td>
                <td>${monitor.cert_grade || '-'}</td>
                <td>${monitor.encryption_type || '-'}</td>
                <td>${monitor.port || 443}</td>
                <td>${monitor.ip_type || 'domain'}</td>
                <td>${monitor.ip_address || '-'}</td>
                <td>${getStatusBadge(monitor.status || 'normal')}</td>
                <td>${monitor.valid_days !== undefined ? monitor.valid_days : '-'}</td>
                <td>
                    <div class="form-check form-switch">
                        <input class="form-check-input monitor-toggle" type="checkbox" role="switch" 
                            id="monitorSwitch-${monitor.id}" ${monitor.enabled ? 'checked' : ''}
                            data-id="${monitor.id}">
                    </div>
                </td>
                <td>${monitor.notes || '-'}</td>
                <td>
                    <div class="btn-group btn-group-sm" role="group">
                        <button type="button" class="btn btn-outline-primary btn-check" data-id="${monitor.id}" title="检测">
                            <i class="bi bi-arrow-repeat"></i>
                        </button>
                        <button type="button" class="btn btn-outline-secondary btn-edit" data-id="${monitor.id}" title="编辑">
                            <i class="bi bi-pencil"></i>
                        </button>
                        <button type="button" class="btn btn-outline-danger btn-delete" data-id="${monitor.id}" title="删除">
                            <i class="bi bi-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    });
    
    monitorListEl.innerHTML = html;
    
    // 绑定监控开关事件
    document.querySelectorAll('.monitor-toggle').forEach(toggle => {
        toggle.addEventListener('change', (e) => {
            const monitorId = e.target.getAttribute('data-id');
            const enabled = e.target.checked;
            toggleMonitor(monitorId, enabled);
        });
    });
}

// 绑定事件
function bindEvents() {
    // 搜索按钮点击事件
    document.getElementById('searchBtn').addEventListener('click', () => {
        const searchValue = document.getElementById('searchInput').value.trim();
        loadMonitors(1, 10, searchValue);
    });
    
    // 搜索框回车事件
    document.getElementById('searchInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const searchValue = document.getElementById('searchInput').value.trim();
            loadMonitors(1, 10, searchValue);
        }
    });
    
    // 有效期排序按钮
    document.getElementById('sortByValidDaysAsc').addEventListener('click', () => {
        loadMonitors(1, 10, document.getElementById('searchInput').value.trim(), 'valid_days:asc');
    });
    
    document.getElementById('sortByValidDaysDesc').addEventListener('click', () => {
        loadMonitors(1, 10, document.getElementById('searchInput').value.trim(), 'valid_days:desc');
    });
    
    // IP类型选择变化事件
    const ipTypeSelect = document.getElementById('ipTypeSelect');
    if (ipTypeSelect) {
        ipTypeSelect.addEventListener('change', (e) => {
            const ipAddressGroup = document.getElementById('ipAddressGroup');
            if (e.target.value === 'domain') {
                ipAddressGroup.querySelector('label').textContent = 'IP地址';
                ipAddressGroup.querySelector('input').placeholder = '可选，留空则自动解析';
            } else {
                ipAddressGroup.querySelector('label').textContent = 'IP地址 *';
                ipAddressGroup.querySelector('input').placeholder = '请输入IP地址';
                ipAddressGroup.querySelector('input').required = true;
            }
        });
    }
    
    // 保存监控按钮
    document.getElementById('saveMonitorBtn').addEventListener('click', () => {
        saveMonitor();
    });
    
    // 监控详情模态框显示事件
    const monitorDetailModal = document.getElementById('monitorDetailModal');
    if (monitorDetailModal) {
        monitorDetailModal.addEventListener('show.bs.modal', (e) => {
            const button = e.relatedTarget;
            if (button) {
                const monitorId = button.getAttribute('data-id');
                loadMonitorDetails(monitorId);
            }
        });
    }
    
    // 立即检测按钮
    document.getElementById('checkNowBtn').addEventListener('click', () => {
        const monitorId = document.getElementById('saveMonitorNotesBtn').getAttribute('data-id');
        checkMonitorNow(monitorId);
    });
    
    // 保存备注按钮
    document.getElementById('saveMonitorNotesBtn').addEventListener('click', () => {
        saveMonitorNotes();
    });
    
    // 动态绑定检测、编辑、删除按钮事件
    document.getElementById('monitorList').addEventListener('click', (e) => {
        const target = e.target.closest('button');
        if (!target) return;
        
        const monitorId = target.getAttribute('data-id');
        
        if (target.classList.contains('btn-check')) {
            // 立即检测
            checkMonitorNow(monitorId);
        } else if (target.classList.contains('btn-edit')) {
            // 打开监控详情模态框
            const modal = new bootstrap.Modal(document.getElementById('monitorDetailModal'));
            loadMonitorDetails(monitorId);
            modal.show();
        } else if (target.classList.contains('btn-delete')) {
            // 删除监控
            if (confirm('确定要删除此监控吗？此操作不可恢复。')) {
                deleteMonitor(monitorId);
            }
        }
    });
}

// 保存监控
async function saveMonitor() {
    const host = document.getElementById('hostInput').value.trim();
    const port = document.getElementById('portInput').value.trim();
    const ipType = document.getElementById('ipTypeSelect').value;
    const ipAddress = document.getElementById('ipAddressInput').value.trim();
    const certificateId = document.getElementById('certificateSelect').value;
    const checkInterval = document.getElementById('checkIntervalInput').value.trim();
    const enabled = document.getElementById('enabledCheck').checked;
    const notes = document.getElementById('notesInput').value.trim();
    
    if (!host || !port) {
        showToast('错误', '请填写必填字段', 'danger');
        return;
    }
    
    if (ipType !== 'domain' && !ipAddress) {
        showToast('错误', '请填写IP地址', 'danger');
        return;
    }
    
    try {
        // 显示保存中状态
        document.getElementById('saveMonitorBtn').disabled = true;
        document.getElementById('saveMonitorBtn').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 保存中...';
        
        // 调用API保存监控
        const response = await apiRequest('/monitors', 'POST', {
            host,
            port: parseInt(port) || 443,
            ip_type: ipType,
            ip_address: ipAddress,
            certificate_id: certificateId || null,
            check_interval: parseInt(checkInterval) || 1440,
            enabled,
            notes
        });
        
        // 恢复按钮状态
        document.getElementById('saveMonitorBtn').disabled = false;
        document.getElementById('saveMonitorBtn').innerHTML = '保存';
        
        if (response && response.success) {
            // 保存成功
            showToast('成功', '监控已保存', 'success');
            
            // 关闭模态框
            const modal = bootstrap.Modal.getInstance(document.getElementById('addMonitorModal'));
            modal.hide();
            
            // 重置表单
            document.getElementById('addMonitorForm').reset();
            
            // 重新加载监控列表
            loadMonitors();
        } else {
            // 保存失败
            showToast('错误', response?.message || '保存监控失败', 'danger');
        }
    } catch (error) {
        console.error('保存监控失败:', error);
        document.getElementById('saveMonitorBtn').disabled = false;
        document.getElementById('saveMonitorBtn').innerHTML = '保存';
        showToast('错误', '保存监控失败', 'danger');
    }
}

// 加载监控详情
async function loadMonitorDetails(monitorId) {
    try {
        // 调用API获取监控详情
        const response = await apiRequest(`/monitors/${monitorId}`);
        
        if (!response || !response.data) {
            showToast('错误', '加载监控详情失败', 'danger');
            return;
        }
        
        const monitor = response.data;
        
        // 填充监控详情
        document.getElementById('detailHost').textContent = monitor.host || '-';
        document.getElementById('detailPort').textContent = monitor.port || 443;
        document.getElementById('detailIP').textContent = monitor.ip_address || '-';
        document.getElementById('detailCertGrade').textContent = monitor.cert_grade || '-';
        document.getElementById('detailEncryption').textContent = monitor.encryption_type || '-';
        document.getElementById('detailValidDays').textContent = monitor.valid_days !== undefined ? monitor.valid_days : '-';
        document.getElementById('detailStatus').innerHTML = getStatusBadge(monitor.status || 'normal');
        document.getElementById('detailLastCheck').textContent = formatDateTime(monitor.last_check) || '-';
        document.getElementById('detailCheckInterval').textContent = `${monitor.check_interval || 1440} 分钟`;
        document.getElementById('detailNotes').textContent = monitor.notes || '-';
        document.getElementById('editMonitorNotesInput').value = monitor.notes || '';
        
        // 保存监控ID到保存按钮
        document.getElementById('saveMonitorNotesBtn').setAttribute('data-id', monitor.id);
        
        // 加载监控历史记录
        loadMonitorHistory(monitorId);
        
    } catch (error) {
        console.error('加载监控详情失败:', error);
        showToast('错误', '加载监控详情失败', 'danger');
    }
}

// 加载监控历史记录
async function loadMonitorHistory(monitorId) {
    try {
        // 调用API获取监控历史记录
        const response = await apiRequest(`/monitors/${monitorId}/history`);
        
        if (!response || !response.data) {
            document.getElementById('monitorHistoryList').innerHTML = '<tr><td colspan="6" class="text-center">加载失败，请重试</td></tr>';
            return;
        }
        
        const history = response.data;
        
        if (!history || history.length === 0) {
            document.getElementById('monitorHistoryList').innerHTML = '<tr><td colspan="6" class="text-center">暂无历史记录</td></tr>';
            return;
        }
        
        let html = '';
        
        history.forEach(record => {
            html += `
                <tr>
                    <td>${formatDateTime(record.check_time) || '-'}</td>
                    <td>${getStatusBadge(record.status || 'normal')}</td>
                    <td>${record.valid_days !== undefined ? record.valid_days : '-'}</td>
                    <td>${record.cert_grade || '-'}</td>
                    <td>${record.encryption_type || '-'}</td>
                    <td>${record.error_message || '-'}</td>
                </tr>
            `;
        });
        
        document.getElementById('monitorHistoryList').innerHTML = html;
        
    } catch (error) {
        console.error('加载监控历史记录失败:', error);
        document.getElementById('monitorHistoryList').innerHTML = '<tr><td colspan="6" class="text-center">加载失败，请重试</td></tr>';
    }
}

// 保存监控备注
async function saveMonitorNotes() {
    const monitorId = document.getElementById('saveMonitorNotesBtn').getAttribute('data-id');
    const notes = document.getElementById('editMonitorNotesInput').value.trim();
    
    try {
        // 调用API保存监控备注
        const response = await apiRequest(`/monitors/${monitorId}`, 'PATCH', {
            notes: notes
        });
        
        if (response && response.success) {
            // 保存成功
            showToast('成功', '备注已保存', 'success');
            
            // 更新显示
            document.getElementById('detailNotes').textContent = notes || '-';
            
            // 重新加载监控列表
            loadMonitors();
        } else {
            // 保存失败
            showToast('错误', response?.message || '保存备注失败', 'danger');
        }
    } catch (error) {
        console.error('保存监控备注失败:', error);
        showToast('错误', '保存备注失败', 'danger');
    }
}

// 切换监控状态
async function toggleMonitor(monitorId, enabled) {
    try {
        // 调用API切换监控状态
        const response = await apiRequest(`/monitors/${monitorId}`, 'PATCH', {
            enabled: enabled
        });
        
        if (response && response.success) {
            // 切换成功
            showToast('成功', `监控已${enabled ? '启用' : '禁用'}`, 'success');
        } else {
            // 切换失败
            showToast('错误', response?.message || '切换监控状态失败', 'danger');
            
            // 恢复开关状态
            document.getElementById(`monitorSwitch-${monitorId}`).checked = !enabled;
        }
    } catch (error) {
        console.error('切换监控状态失败:', error);
        showToast('错误', '切换监控状态失败', 'danger');
        
        // 恢复开关状态
        document.getElementById(`monitorSwitch-${monitorId}`).checked = !enabled;
    }
}

// 立即检测监控
async function checkMonitorNow(monitorId) {
    try {
        // 显示检测中状态
        const checkBtn = document.querySelector(`.btn-check[data-id="${monitorId}"]`);
        if (checkBtn) {
            checkBtn.disabled = true;
            checkBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
        }
        
        const checkNowBtn = document.getElementById('checkNowBtn');
        if (checkNowBtn) {
            checkNowBtn.disabled = true;
            checkNowBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 检测中...';
        }
        
        // 调用API立即检测
        const response = await apiRequest(`/monitors/${monitorId}/check`, 'POST');
        
        // 恢复按钮状态
        if (checkBtn) {
            checkBtn.disabled = false;
            checkBtn.innerHTML = '<i class="bi bi-arrow-repeat"></i>';
        }
        
        if (checkNowBtn) {
            checkNowBtn.disabled = false;
            checkNowBtn.innerHTML = '立即检测';
        }
        
        if (response && response.success) {
            // 检测成功
            showToast('成功', '检测已完成', 'success');
            
            // 重新加载监控详情和列表
            if (document.getElementById('monitorDetailModal').classList.contains('show')) {
                loadMonitorDetails(monitorId);
            }
            
            loadMonitors();
        } else {
            // 检测失败
            showToast('错误', response?.message || '检测失败', 'danger');
        }
    } catch (error) {
        console.error('检测失败:', error);
        
        // 恢复按钮状态
        const checkBtn = document.querySelector(`.btn-check[data-id="${monitorId}"]`);
        if (checkBtn) {
            checkBtn.disabled = false;
            checkBtn.innerHTML = '<i class="bi bi-arrow-repeat"></i>';
        }
        
        const checkNowBtn = document.getElementById('checkNowBtn');
        if (checkNowBtn) {
            checkNowBtn.disabled = false;
            checkNowBtn.innerHTML = '立即检测';
        }
        
        showToast('错误', '检测失败', 'danger');
    }
}

// 删除监控
async function deleteMonitor(monitorId) {
    try {
        // 调用API删除监控
        const response = await apiRequest(`/monitors/${monitorId}`, 'DELETE');
        
        if (response && response.success) {
            // 删除成功
            showToast('成功', '监控已删除', 'success');
            
            // 重新加载监控列表
            loadMonitors();
        } else {
            // 删除失败
            showToast('错误', response?.message || '删除监控失败', 'danger');
        }
    } catch (error) {
        console.error('删除监控失败:', error);
        showToast('错误', '删除监控失败', 'danger');
    }
}
