// 自动部署页面的JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // 检查用户登录状态
    if (!checkAuth()) return;
    
    // 初始化页面
    initServersPage();
    
    // 绑定事件
    bindEvents();
});

// 初始化服务器管理页面
async function initServersPage() {
    // 加载服务器列表
    await loadServers();
    
    // 初始化认证方式切换
    initAuthTypeToggle();
}

// 加载服务器列表
async function loadServers(page = 1, limit = 10, search = '') {
    try {
        // 显示加载中状态
        document.getElementById('serverList').innerHTML = '<tr><td colspan="10" class="text-center">加载中...</td></tr>';
        
        // 构建查询参数
        const queryParams = new URLSearchParams({
            page: page,
            limit: limit
        });
        
        if (search) {
            queryParams.append('search', search);
        }
        
        // 调用API获取服务器列表
        const response = await apiRequest(`/servers?${queryParams.toString()}`);
        
        if (!response || !response.data) {
            document.getElementById('serverList').innerHTML = '<tr><td colspan="10" class="text-center">加载失败，请重试</td></tr>';
            return;
        }
        
        const { servers, total, totalPages } = response.data;
        
        // 渲染服务器列表
        renderServerList(servers);
        
        // 创建分页
        createPagination(page, totalPages, (newPage) => {
            loadServers(newPage, limit, search);
        });
        
    } catch (error) {
        console.error('加载服务器列表失败:', error);
        document.getElementById('serverList').innerHTML = '<tr><td colspan="10" class="text-center">加载失败，请重试</td></tr>';
    }
}

// 渲染服务器列表
function renderServerList(servers) {
    const serverListEl = document.getElementById('serverList');
    
    if (!servers || servers.length === 0) {
        serverListEl.innerHTML = '<tr><td colspan="10" class="text-center">暂无服务器数据</td></tr>';
        return;
    }
    
    let html = '';
    
    servers.forEach(server => {
        html += `
            <tr data-id="${server.id}">
                <td>${server.type || 'nginx'}</td>
                <td>${server.name || '-'}</td>
                <td>${server.os_type || '-'} ${server.os_version || ''}</td>
                <td>${server.ip_address || '-'}</td>
                <td>${server.version || '-'}</td>
                <td>${getStatusBadge(server.status || 'normal')}</td>
                <td>${formatDateTime(server.last_updated) || '-'}</td>
                <td>
                    <div class="form-check form-switch">
                        <input class="form-check-input auto-deploy-toggle" type="checkbox" role="switch" 
                            id="autoDeploySwitch-${server.id}" ${server.auto_deploy ? 'checked' : ''}
                            data-id="${server.id}">
                    </div>
                </td>
                <td>${server.notes || '-'}</td>
                <td>
                    <div class="btn-group btn-group-sm" role="group">
                        <button type="button" class="btn btn-outline-primary btn-edit" data-id="${server.id}" title="编辑">
                            <i class="bi bi-pencil"></i>
                        </button>
                        <button type="button" class="btn btn-outline-danger btn-delete" data-id="${server.id}" title="删除">
                            <i class="bi bi-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    });
    
    serverListEl.innerHTML = html;
    
    // 绑定自动部署开关事件
    document.querySelectorAll('.auto-deploy-toggle').forEach(toggle => {
        toggle.addEventListener('change', (e) => {
            const serverId = e.target.getAttribute('data-id');
            const enabled = e.target.checked;
            toggleAutoDeploy(serverId, enabled);
        });
    });
}

// 初始化认证方式切换
function initAuthTypeToggle() {
    const authTypeSelect = document.getElementById('authTypeSelect');
    const passwordGroup = document.getElementById('passwordGroup');
    const privateKeyGroup = document.getElementById('privateKeyGroup');
    
    if (authTypeSelect) {
        authTypeSelect.addEventListener('change', (e) => {
            if (e.target.value === 'password') {
                passwordGroup.classList.remove('d-none');
                privateKeyGroup.classList.add('d-none');
            } else {
                passwordGroup.classList.add('d-none');
                privateKeyGroup.classList.remove('d-none');
            }
        });
    }
}

// 绑定事件
function bindEvents() {
    // 搜索按钮点击事件
    document.getElementById('searchBtn').addEventListener('click', () => {
        const searchValue = document.getElementById('searchInput').value.trim();
        loadServers(1, 10, searchValue);
    });
    
    // 搜索框回车事件
    document.getElementById('searchInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const searchValue = document.getElementById('searchInput').value.trim();
            loadServers(1, 10, searchValue);
        }
    });
    
    // 测试连接按钮
    document.getElementById('testConnectionBtn').addEventListener('click', () => {
        testServerConnection();
    });
    
    // 保存服务器按钮
    document.getElementById('saveServerBtn').addEventListener('click', () => {
        saveServer();
    });
    
    // 服务器详情模态框显示事件
    const serverDetailModal = document.getElementById('serverDetailModal');
    if (serverDetailModal) {
        serverDetailModal.addEventListener('show.bs.modal', (e) => {
            const button = e.relatedTarget;
            if (button) {
                const serverId = button.getAttribute('data-id');
                loadServerDetails(serverId);
            }
        });
    }
    
    // 测试连接按钮（详情模态框）
    document.getElementById('testConnectionDetailBtn').addEventListener('click', () => {
        const serverId = document.getElementById('saveServerNotesBtn').getAttribute('data-id');
        testServerConnectionById(serverId);
    });
    
    // 保存备注按钮
    document.getElementById('saveServerNotesBtn').addEventListener('click', () => {
        saveServerNotes();
    });
    
    // 立即部署按钮
    document.getElementById('deployNowBtn').addEventListener('click', () => {
        deployCertificate();
    });
    
    // 动态绑定编辑、删除按钮事件
    document.getElementById('serverList').addEventListener('click', (e) => {
        const target = e.target.closest('button');
        if (!target) return;
        
        const serverId = target.getAttribute('data-id');
        
        if (target.classList.contains('btn-edit')) {
            // 打开服务器详情模态框
            const modal = new bootstrap.Modal(document.getElementById('serverDetailModal'));
            loadServerDetails(serverId);
            modal.show();
        } else if (target.classList.contains('btn-delete')) {
            // 删除服务器
            if (confirm('确定要删除此服务器吗？此操作不可恢复。')) {
                deleteServer(serverId);
            }
        }
    });
}

// 测试服务器连接
async function testServerConnection() {
    const hostname = document.getElementById('hostnameInput').value.trim();
    const port = document.getElementById('portInput').value.trim();
    const username = document.getElementById('usernameInput').value.trim();
    const authType = document.getElementById('authTypeSelect').value;
    let authData = {};
    
    if (authType === 'password') {
        authData.password = document.getElementById('passwordInput').value;
    } else {
        authData.private_key = document.getElementById('privateKeyInput').value;
    }
    
    if (!hostname || !username) {
        showToast('错误', '请填写主机名和用户名', 'danger');
        return;
    }
    
    try {
        // 显示测试中状态
        document.getElementById('testConnectionBtn').disabled = true;
        document.getElementById('testConnectionBtn').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 测试中...';
        
        // 调用API测试连接
        const response = await apiRequest('/servers/test-connection', 'POST', {
            hostname,
            port: parseInt(port) || 22,
            username,
            auth_type: authType,
            auth_data: authData
        });
        
        // 恢复按钮状态
        document.getElementById('testConnectionBtn').disabled = false;
        document.getElementById('testConnectionBtn').innerHTML = '测试连接';
        
        if (response && response.success) {
            // 连接成功
            showToast('成功', '服务器连接测试成功', 'success');
        } else {
            // 连接失败
            showToast('错误', response?.message || '服务器连接测试失败', 'danger');
        }
    } catch (error) {
        console.error('服务器连接测试失败:', error);
        document.getElementById('testConnectionBtn').disabled = false;
        document.getElementById('testConnectionBtn').innerHTML = '测试连接';
        showToast('错误', '服务器连接测试失败', 'danger');
    }
}

// 根据ID测试服务器连接
async function testServerConnectionById(serverId) {
    try {
        // 显示测试中状态
        document.getElementById('testConnectionDetailBtn').disabled = true;
        document.getElementById('testConnectionDetailBtn').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 测试中...';
        
        // 调用API测试连接
        const response = await apiRequest(`/servers/${serverId}/test-connection`, 'POST');
        
        // 恢复按钮状态
        document.getElementById('testConnectionDetailBtn').disabled = false;
        document.getElementById('testConnectionDetailBtn').innerHTML = '测试连接';
        
        if (response && response.success) {
            // 连接成功
            showToast('成功', '服务器连接测试成功', 'success');
        } else {
            // 连接失败
            showToast('错误', response?.message || '服务器连接测试失败', 'danger');
        }
    } catch (error) {
        console.error('服务器连接测试失败:', error);
        document.getElementById('testConnectionDetailBtn').disabled = false;
        document.getElementById('testConnectionDetailBtn').innerHTML = '测试连接';
        showToast('错误', '服务器连接测试失败', 'danger');
    }
}

// 保存服务器
async function saveServer() {
    const name = document.getElementById('serverNameInput').value.trim();
    const type = document.getElementById('serverTypeSelect').value;
    const hostname = document.getElementById('hostnameInput').value.trim();
    const ipAddress = document.getElementById('ipAddressInput').value.trim();
    const osType = document.getElementById('osTypeInput').value.trim();
    const osVersion = document.getElementById('osVersionInput').value.trim();
    const version = document.getElementById('versionInput').value.trim();
    const port = document.getElementById('portInput').value.trim();
    const username = document.getElementById('usernameInput').value.trim();
    const authType = document.getElementById('authTypeSelect').value;
    const autoDeploy = document.getElementById('autoDeployCheck').checked;
    const notes = document.getElementById('notesInput').value.trim();
    
    let authData = {};
    
    if (authType === 'password') {
        authData.password = document.getElementById('passwordInput').value;
    } else {
        authData.private_key = document.getElementById('privateKeyInput').value;
    }
    
    if (!name || !hostname || !ipAddress || !osType || !username) {
        showToast('错误', '请填写必填字段', 'danger');
        return;
    }
    
    try {
        // 显示保存中状态
        document.getElementById('saveServerBtn').disabled = true;
        document.getElementById('saveServerBtn').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 保存中...';
        
        // 调用API保存服务器
        const response = await apiRequest('/servers', 'POST', {
            name,
            type,
            hostname,
            ip_address: ipAddress,
            os_type: osType,
            os_version: osVersion,
            version,
            port: parseInt(port) || 22,
            username,
            auth_type: authType,
            auth_data: authData,
            auto_deploy: autoDeploy,
            notes
        });
        
        // 恢复按钮状态
        document.getElementById('saveServerBtn').disabled = false;
        document.getElementById('saveServerBtn').innerHTML = '保存';
        
        if (response && response.success) {
            // 保存成功
            showToast('成功', '服务器已保存', 'success');
            
            // 关闭模态框
            const modal = bootstrap.Modal.getInstance(document.getElementById('addServerModal'));
            modal.hide();
            
            // 重置表单
            document.getElementById('addServerForm').reset();
            
            // 重新加载服务器列表
            loadServers();
        } else {
            // 保存失败
            showToast('错误', response?.message || '保存服务器失败', 'danger');
        }
    } catch (error) {
        console.error('保存服务器失败:', error);
        document.getElementById('saveServerBtn').disabled = false;
        document.getElementById('saveServerBtn').innerHTML = '保存';
        showToast('错误', '保存服务器失败', 'danger');
    }
}

// 加载服务器详情
async function loadServerDetails(serverId) {
    try {
        // 调用API获取服务器详情
        const response = await apiRequest(`/servers/${serverId}`);
        
        if (!response || !response.data) {
            showToast('错误', '加载服务器详情失败', 'danger');
            return;
        }
        
        const server = response.data;
        
        // 填充服务器详情
        document.getElementById('detailName').textContent = server.name || '-';
        document.getElementById('detailType').textContent = server.type || 'nginx';
        document.getElementById('detailIP').textContent = server.ip_address || '-';
        document.getElementById('detailOS').textContent = `${server.os_type || '-'} ${server.os_version || ''}`;
        document.getElementById('detailVersion').textContent = server.version || '-';
        document.getElementById('detailStatus').innerHTML = getStatusBadge(server.status || 'normal');
        document.getElementById('detailNotes').textContent = server.notes || '-';
        document.getElementById('editServerNotesInput').value = server.notes || '';
        
        // 保存服务器ID到保存按钮
        document.getElementById('saveServerNotesBtn').setAttribute('data-id', server.id);
        
        // 加载已部署证书
        loadDeployedCertificates(serverId);
        
    } catch (error) {
        console.error('加载服务器详情失败:', error);
        showToast('错误', '加载服务器详情失败', 'danger');
    }
}

// 加载已部署证书
async function loadDeployedCertificates(serverId) {
    try {
        // 调用API获取已部署证书
        const response = await apiRequest(`/servers/${serverId}/certificates`);
        
        if (!response || !response.data) {
            document.getElementById('deployedCertsList').innerHTML = '<tr><td colspan="6" class="text-center">加载失败，请重试</td></tr>';
            return;
        }
        
        const deployedCerts = response.data;
        
        if (!deployedCerts || deployedCerts.length === 0) {
            document.getElementById('deployedCertsList').innerHTML = '<tr><td colspan="6" class="text-center">暂无已部署证书</td></tr>';
            return;
        }
        
        let html = '';
        
        deployedCerts.forEach(cert => {
            html += `
                <tr data-id="${cert.id}">
                    <td>${cert.domain}</td>
                    <td>${cert.cert_path || '-'}</td>
                    <td>${cert.key_path || '-'}</td>
                    <td>${getStatusBadge(cert.status || 'normal')}</td>
                    <td>${formatDateTime(cert.last_deployed) || '-'}</td>
                    <td>
                        <div class="btn-group btn-group-sm" role="group">
                            <button type="button" class="btn btn-outline-primary btn-redeploy" data-id="${cert.id}" title="重新部署">
                                <i class="bi bi-arrow-repeat"></i>
                            </button>
                            <button type="button" class="btn btn-outline-danger btn-undeploy" data-id="${cert.id}" title="取消部署">
                                <i class="bi bi-x-circle"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });
        
        document.getElementById('deployedCertsList').innerHTML = html;
        
        // 加载可部署证书
        loadAvailableCertificates(serverId);
        
    } catch (error) {
        console.error('加载已部署证书失败:', error);
        document.getElementById('deployedCertsList').innerHTML = '<tr><td colspan="6" class="text-center">加载失败，请重试</td></tr>';
    }
}

// 加载可部署证书
async function loadAvailableCertificates(serverId) {
    try {
        // 调用API获取可部署证书
        const response = await apiRequest('/certificates?status=valid');
        
        if (!response || !response.data) {
            return;
        }
        
        const { certificates } = response.data;
        
        if (!certificates || certificates.length === 0) {
            document.getElementById('certSelect').innerHTML = '<option value="">暂无可用证书</option>';
            return;
        }
        
        let html = '<option value="">请选择证书</option>';
        
        certificates.forEach(cert => {
            html += `<option value="${cert.id}">${cert.domain} (${cert.ca_type || 'Unknown'}, ${cert.encryption_type || 'Unknown'})</option>`;
        });
        
        document.getElementById('certSelect').innerHTML = html;
        
        // 证书选择变化事件
        document.getElementById('certSelect').addEventListener('change', (e) => {
            const certId = e.target.value;
            if (certId) {
                const selectedCert = certificates.find(c => c.id == certId);
                if (selectedCert) {
                    // 自动填充路径
                    const domain = selectedCert.domain.replace('*.', 'wildcard.');
                    document.getElementById('certPathInput').value = `/etc/nginx/certs/${domain}.crt`;
                    document.getElementById('keyPathInput').value = `/etc/nginx/certs/${domain}.key`;
                    document.getElementById('chainPathInput').value = `/etc/nginx/certs/${domain}.chain.pem`;
                    document.getElementById('configPathInput').value = `/etc/nginx/conf.d/${domain}.conf`;
                }
            }
        });
        
    } catch (error) {
        console.error('加载可部署证书失败:', error);
    }
}

// 保存服务器备注
async function saveServerNotes() {
    const serverId = document.getElementById('saveServerNotesBtn').getAttribute('data-id');
    const notes = document.getElementById('editServerNotesInput').value.trim();
    
    try {
        // 调用API保存服务器备注
        const response = await apiRequest(`/servers/${serverId}`, 'PATCH', {
            notes: notes
        });
        
        if (response && response.success) {
            // 保存成功
            showToast('成功', '备注已保存', 'success');
            
            // 更新显示
            document.getElementById('detailNotes').textContent = notes || '-';
            
            // 重新加载服务器列表
            loadServers();
        } else {
            // 保存失败
            showToast('错误', response?.message || '保存备注失败', 'danger');
        }
    } catch (error) {
        console.error('保存服务器备注失败:', error);
        showToast('错误', '保存备注失败', 'danger');
    }
}

// 切换自动部署
async function toggleAutoDeploy(serverId, enabled) {
    try {
        // 调用API切换自动部署
        const response = await apiRequest(`/servers/${serverId}`, 'PATCH', {
            auto_deploy: enabled
        });
        
        if (response && response.success) {
            // 切换成功
            showToast('成功', `自动部署已${enabled ? '启用' : '禁用'}`, 'success');
        } else {
            // 切换失败
            showToast('错误', response?.message || '切换自动部署失败', 'danger');
            
            // 恢复开关状态
            document.getElementById(`autoDeploySwitch-${serverId}`).checked = !enabled;
        }
    } catch (error) {
        console.error('切换自动部署失败:', error);
        showToast('错误', '切换自动部署失败', 'danger');
        
        // 恢复开关状态
        document.getElementById(`autoDeploySwitch-${serverId}`).checked = !enabled;
    }
}

// 部署证书
async function deployCertificate() {
    const serverId = document.getElementById('saveServerNotesBtn').getAttribute('data-id');
    const certId = document.getElementById('certSelect').value;
    const certPath = document.getElementById('certPathInput').value.trim();
    const keyPath = document.getElementById('keyPathInput').value.trim();
    const chainPath = document.getElementById('chainPathInput').value.trim();
    const configPath = document.getElementById('configPathInput').value.trim();
    const autoDeploy = document.getElementById('autoDeployCheckDeploy').checked;
    const reloadService = document.getElementById('reloadServiceCheck').checked;
    
    if (!certId || !certPath || !keyPath) {
        showToast('错误', '请选择证书并填写必填路径', 'danger');
        return;
    }
    
    try {
        // 显示部署中状态
        document.getElementById('deployNowBtn').disabled = true;
        document.getElementById('deployNowBtn').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 部署中...';
        
        // 调用API部署证书
        const response = await apiRequest(`/servers/${serverId}/deploy`, 'POST', {
            certificate_id: certId,
            cert_path: certPath,
            key_path: keyPath,
            chain_path: chainPath,
            config_path: configPath,
            auto_deploy: autoDeploy,
            reload_service: reloadService
        });
        
        // 恢复按钮状态
        document.getElementById('deployNowBtn').disabled = false;
        document.getElementById('deployNowBtn').innerHTML = '立即部署';
        
        if (response && response.success) {
            // 部署成功
            showToast('成功', '证书已成功部署', 'success');
            
            // 关闭模态框
            const modal = bootstrap.Modal.getInstance(document.getElementById('deployCertModal'));
            modal.hide();
            
            // 重新加载已部署证书
            loadDeployedCertificates(serverId);
        } else {
            // 部署失败
            showToast('错误', response?.message || '证书部署失败', 'danger');
        }
    } catch (error) {
        console.error('证书部署失败:', error);
        document.getElementById('deployNowBtn').disabled = false;
        document.getElementById('deployNowBtn').innerHTML = '立即部署';
        showToast('错误', '证书部署失败', 'danger');
    }
}

// 删除服务器
async function deleteServer(serverId) {
    try {
        // 调用API删除服务器
        const response = await apiRequest(`/servers/${serverId}`, 'DELETE');
        
        if (response && response.success) {
            // 删除成功
            showToast('成功', '服务器已删除', 'success');
            
            // 重新加载服务器列表
            loadServers();
        } else {
            // 删除失败
            showToast('错误', response?.message || '删除服务器失败', 'danger');
        }
    } catch (error) {
        console.error('删除服务器失败:', error);
        showToast('错误', '删除服务器失败', 'danger');
    }
}
