// 证书管理页面的JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // 检查用户登录状态
    if (!checkAuth()) return;
    
    // 初始化页面
    initCertificatesPage();
    
    // 绑定事件
    bindEvents();
});

// 初始化证书管理页面
async function initCertificatesPage() {
    // 加载证书列表
    await loadCertificates();
}

// 加载证书列表
async function loadCertificates(page = 1, limit = 10, search = '') {
    try {
        // 显示加载中状态
        document.getElementById('certificateList').innerHTML = '<tr><td colspan="9" class="text-center">加载中...</td></tr>';
        
        // 构建查询参数
        const queryParams = new URLSearchParams({
            page: page,
            limit: limit
        });
        
        if (search) {
            queryParams.append('search', search);
        }
        
        // 调用API获取证书列表
        const response = await apiRequest(`/certificates?${queryParams.toString()}`);
        
        if (!response || !response.data) {
            document.getElementById('certificateList').innerHTML = '<tr><td colspan="9" class="text-center">加载失败，请重试</td></tr>';
            return;
        }
        
        const { certificates, total, totalPages } = response.data;
        
        // 渲染证书列表
        renderCertificateList(certificates);
        
        // 创建分页
        createPagination(page, totalPages, (newPage) => {
            loadCertificates(newPage, limit, search);
        });
        
    } catch (error) {
        console.error('加载证书列表失败:', error);
        document.getElementById('certificateList').innerHTML = '<tr><td colspan="9" class="text-center">加载失败，请重试</td></tr>';
    }
}

// 渲染证书列表
function renderCertificateList(certificates) {
    const certificateListEl = document.getElementById('certificateList');
    
    if (!certificates || certificates.length === 0) {
        certificateListEl.innerHTML = '<tr><td colspan="9" class="text-center">暂无证书数据</td></tr>';
        return;
    }
    
    let html = '';
    
    certificates.forEach(cert => {
        const validDays = calculateRemainingDays(cert.valid_to);
        const status = validDays > 0 ? 'valid' : 'expired';
        
        html += `
            <tr data-id="${cert.id}">
                <td>
                    <input type="checkbox" class="cert-checkbox" value="${cert.id}">
                </td>
                <td>${cert.domain}</td>
                <td>${cert.dns_verified ? '<span class="badge bg-success">已验证</span>' : '<span class="badge bg-warning text-dark">未验证</span>'}</td>
                <td>${cert.ca_type || '-'}</td>
                <td>${validDays}</td>
                <td>${cert.encryption_type || '-'}</td>
                <td>${getStatusBadge(status, validDays)}</td>
                <td>${cert.notes || '-'}</td>
                <td>
                    <div class="btn-group btn-group-sm" role="group">
                        <button type="button" class="btn btn-outline-primary btn-edit" data-id="${cert.id}" title="编辑">
                            <i class="bi bi-pencil"></i>
                        </button>
                        <button type="button" class="btn btn-outline-success btn-download" data-id="${cert.id}" title="下载">
                            <i class="bi bi-download"></i>
                        </button>
                        <button type="button" class="btn btn-outline-danger btn-delete" data-id="${cert.id}" title="删除">
                            <i class="bi bi-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    });
    
    certificateListEl.innerHTML = html;
}

// 绑定事件
function bindEvents() {
    // 搜索按钮点击事件
    document.getElementById('searchBtn').addEventListener('click', () => {
        const searchValue = document.getElementById('searchInput').value.trim();
        loadCertificates(1, 10, searchValue);
    });
    
    // 搜索框回车事件
    document.getElementById('searchInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const searchValue = document.getElementById('searchInput').value.trim();
            loadCertificates(1, 10, searchValue);
        }
    });
    
    // 全选/取消全选
    document.getElementById('selectAllCerts').addEventListener('change', (e) => {
        const checkboxes = document.querySelectorAll('.cert-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.checked = e.target.checked;
        });
    });
    
    // 删除失效证书按钮
    document.getElementById('deleteExpiredBtn').addEventListener('click', () => {
        if (confirm('确定要删除所有失效证书吗？此操作不可恢复。')) {
            deleteExpiredCertificates();
        }
    });
    
    // 验证域名按钮
    document.getElementById('verifyDomainBtn').addEventListener('click', () => {
        verifyDomain();
    });
    
    // 提交申请按钮
    document.getElementById('submitCertBtn').addEventListener('click', () => {
        submitCertificateApplication();
    });
    
    // 域名输入框变化事件
    document.getElementById('domainInput').addEventListener('input', () => {
        updateDnsRecords();
    });
    
    // 证书详情模态框显示事件
    const certDetailModal = document.getElementById('certDetailModal');
    if (certDetailModal) {
        certDetailModal.addEventListener('show.bs.modal', (e) => {
            const button = e.relatedTarget;
            const certId = button.getAttribute('data-id');
            loadCertificateDetails(certId);
        });
    }
    
    // 保存备注按钮
    document.getElementById('saveNotesBtn').addEventListener('click', () => {
        saveCertificateNotes();
    });
    
    // 动态绑定编辑、下载、删除按钮事件
    document.getElementById('certificateList').addEventListener('click', (e) => {
        const target = e.target.closest('button');
        if (!target) return;
        
        const certId = target.getAttribute('data-id');
        
        if (target.classList.contains('btn-edit')) {
            // 打开证书详情模态框
            const modal = new bootstrap.Modal(document.getElementById('certDetailModal'));
            loadCertificateDetails(certId);
            modal.show();
        } else if (target.classList.contains('btn-download')) {
            // 下载证书
            downloadCertificate(certId);
        } else if (target.classList.contains('btn-delete')) {
            // 删除证书
            if (confirm('确定要删除此证书吗？此操作不可恢复。')) {
                deleteCertificate(certId);
            }
        }
    });
}

// 更新DNS记录
function updateDnsRecords() {
    const domain = document.getElementById('domainInput').value.trim();
    if (!domain) return;
    
    // 更新主机记录
    const dnsHostRecordEl = document.getElementById('dnsHostRecord');
    const dnsRecordValueEl = document.getElementById('dnsRecordValue');
    
    // 生成随机验证值（实际应由后端生成）
    const randomValue = Math.random().toString(36).substring(2, 15);
    
    if (domain.startsWith('*.')) {
        // 通配符域名
        const baseDomain = domain.substring(2);
        dnsHostRecordEl.textContent = `_acme-challenge.${baseDomain}`;
    } else {
        dnsHostRecordEl.textContent = `_acme-challenge.${domain}`;
    }
    
    dnsRecordValueEl.textContent = randomValue;
}

// 验证域名
async function verifyDomain() {
    const domain = document.getElementById('domainInput').value.trim();
    if (!domain) {
        showToast('错误', '请输入域名', 'danger');
        return;
    }
    
    try {
        // 显示验证中状态
        document.getElementById('verifyDomainBtn').disabled = true;
        document.getElementById('verifyDomainBtn').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 验证中...';
        
        // 调用API验证域名
        const response = await apiRequest('/certificates/verify', 'POST', {
            domain: domain
        });
        
        // 恢复按钮状态
        document.getElementById('verifyDomainBtn').disabled = false;
        document.getElementById('verifyDomainBtn').innerHTML = '验证域名';
        
        if (response && response.success) {
            // 验证成功
            document.getElementById('verifySuccessAlert').classList.remove('d-none');
            document.getElementById('verifyFailAlert').classList.add('d-none');
            document.getElementById('submitCertBtn').disabled = false;
        } else {
            // 验证失败
            document.getElementById('verifySuccessAlert').classList.add('d-none');
            document.getElementById('verifyFailAlert').classList.remove('d-none');
            document.getElementById('submitCertBtn').disabled = true;
        }
    } catch (error) {
        console.error('域名验证失败:', error);
        document.getElementById('verifyDomainBtn').disabled = false;
        document.getElementById('verifyDomainBtn').innerHTML = '验证域名';
        document.getElementById('verifySuccessAlert').classList.add('d-none');
        document.getElementById('verifyFailAlert').classList.remove('d-none');
    }
}

// 提交证书申请
async function submitCertificateApplication() {
    const domain = document.getElementById('domainInput').value.trim();
    const caType = document.getElementById('caTypeSelect').value;
    const encryptionType = document.getElementById('encryptionTypeSelect').value;
    const notes = document.getElementById('notesInput').value.trim();
    
    if (!domain) {
        showToast('错误', '请输入域名', 'danger');
        return;
    }
    
    try {
        // 显示提交中状态
        document.getElementById('submitCertBtn').disabled = true;
        document.getElementById('submitCertBtn').innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 提交中...';
        
        // 调用API提交证书申请
        const response = await apiRequest('/certificates', 'POST', {
            domain: domain,
            ca_type: caType,
            encryption_type: encryptionType,
            notes: notes
        });
        
        // 恢复按钮状态
        document.getElementById('submitCertBtn').disabled = false;
        document.getElementById('submitCertBtn').innerHTML = '提交申请';
        
        if (response && response.success) {
            // 申请成功
            showToast('成功', '证书申请已提交', 'success');
            
            // 关闭模态框
            const modal = bootstrap.Modal.getInstance(document.getElementById('applyCertModal'));
            modal.hide();
            
            // 重新加载证书列表
            loadCertificates();
        } else {
            // 申请失败
            showToast('错误', response?.message || '证书申请失败', 'danger');
        }
    } catch (error) {
        console.error('证书申请失败:', error);
        document.getElementById('submitCertBtn').disabled = false;
        document.getElementById('submitCertBtn').innerHTML = '提交申请';
        showToast('错误', '证书申请失败', 'danger');
    }
}

// 加载证书详情
async function loadCertificateDetails(certId) {
    try {
        // 调用API获取证书详情
        const response = await apiRequest(`/certificates/${certId}`);
        
        if (!response || !response.data) {
            showToast('错误', '加载证书详情失败', 'danger');
            return;
        }
        
        const cert = response.data;
        
        // 填充证书详情
        document.getElementById('detailDomain').textContent = cert.domain;
        document.getElementById('detailCAType').textContent = cert.ca_type || '-';
        document.getElementById('detailEncryption').textContent = cert.encryption_type || '-';
        document.getElementById('detailValidFrom').textContent = formatDateTime(cert.valid_from);
        document.getElementById('detailValidTo').textContent = formatDateTime(cert.valid_to);
        document.getElementById('detailCreatedAt').textContent = formatDateTime(cert.created_at);
        document.getElementById('detailNotes').textContent = cert.notes || '-';
        document.getElementById('editNotesInput').value = cert.notes || '';
        
        // 保存证书ID到保存按钮
        document.getElementById('saveNotesBtn').setAttribute('data-id', cert.id);
        
    } catch (error) {
        console.error('加载证书详情失败:', error);
        showToast('错误', '加载证书详情失败', 'danger');
    }
}

// 保存证书备注
async function saveCertificateNotes() {
    const certId = document.getElementById('saveNotesBtn').getAttribute('data-id');
    const notes = document.getElementById('editNotesInput').value.trim();
    
    try {
        // 调用API保存证书备注
        const response = await apiRequest(`/certificates/${certId}`, 'PATCH', {
            notes: notes
        });
        
        if (response && response.success) {
            // 保存成功
            showToast('成功', '备注已保存', 'success');
            
            // 更新显示
            document.getElementById('detailNotes').textContent = notes || '-';
            
            // 重新加载证书列表
            loadCertificates();
        } else {
            // 保存失败
            showToast('错误', response?.message || '保存备注失败', 'danger');
        }
    } catch (error) {
        console.error('保存证书备注失败:', error);
        showToast('错误', '保存备注失败', 'danger');
    }
}

// 下载证书
async function downloadCertificate(certId) {
    try {
        // 调用API下载证书
        window.location.href = `${API_BASE_URL}/certificates/${certId}/download?token=${localStorage.getItem('auth_token')}`;
    } catch (error) {
        console.error('下载证书失败:', error);
        showToast('错误', '下载证书失败', 'danger');
    }
}

// 删除证书
async function deleteCertificate(certId) {
    try {
        // 调用API删除证书
        const response = await apiRequest(`/certificates/${certId}`, 'DELETE');
        
        if (response && response.success) {
            // 删除成功
            showToast('成功', '证书已删除', 'success');
            
            // 重新加载证书列表
            loadCertificates();
        } else {
            // 删除失败
            showToast('错误', response?.message || '删除证书失败', 'danger');
        }
    } catch (error) {
        console.error('删除证书失败:', error);
        showToast('错误', '删除证书失败', 'danger');
    }
}

// 删除失效证书
async function deleteExpiredCertificates() {
    try {
        // 调用API删除失效证书
        const response = await apiRequest('/certificates/expired', 'DELETE');
        
        if (response && response.success) {
            // 删除成功
            showToast('成功', '所有失效证书已删除', 'success');
            
            // 重新加载证书列表
            loadCertificates();
        } else {
            // 删除失败
            showToast('错误', response?.message || '删除失效证书失败', 'danger');
        }
    } catch (error) {
        console.error('删除失效证书失败:', error);
        showToast('错误', '删除失效证书失败', 'danger');
    }
}
