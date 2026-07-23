// AUDIT-050: IIFE-wrapped so module state (servers/channels/commands) and
// every function stay out of the global window scope, matching every other
// admin-*.js file (see lessons.md "Blank Admin Pages"). Full ES6->ES5
// conversion of the function bodies is tracked separately as AUDIT-131.
(function () {
    'use strict';

var servers = [];
var channels = [];
var commands = [];

async function apiCall(url, options = {}) {
    await AdminCommon.fetchCsrfToken();
    const csrfToken = AdminCommon.getCsrfToken();
    const headers = {
        'Content-Type': 'application/json',
        ...(csrfToken && { 'X-CSRF-Token': csrfToken }),
        ...options.headers
    };
    
    const response = await fetch(url, { ...options, headers });
    const data = await response.json();
    
    if (!response.ok) {
        throw new Error(data.error || 'Request failed');
    }
    return data;
}

var alertTimer = null;
function showAlert(message, isError = true) {
    const alertDiv = document.getElementById('alertMessage');
    // AUDIT-062: toggle the shared .hidden class instead of inline
    // style.display, and clear any pending hide-timer first so back-to-back
    // alerts don't hide each other early. Setting className (error/success)
    // also drops .hidden, making the alert visible.
    alertDiv.className = isError ? 'error' : 'success';
    alertDiv.textContent = message;
    if (alertTimer) clearTimeout(alertTimer);
    alertTimer = setTimeout(function() { alertDiv.classList.add('hidden'); }, 5000);
}

function switchTab(tabName, clickedBtn) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

    if (clickedBtn) clickedBtn.classList.add('active');
    document.getElementById('tab-' + tabName).classList.add('active');

    if (tabName === 'servers') loadServers();
    else if (tabName === 'channels') loadChannels();
    else if (tabName === 'commands') loadCommands();
    else if (tabName === 'send') loadServersForSend();
}

function getStatusClass(status) {
    switch (status) {
        case 'connected': return 'status-connected';
        case 'disconnected': return 'status-disconnected';
        case 'connecting': return 'status-connecting';
        case 'error': return 'status-error';
        case 'joined': return 'status-joined';
        case 'pending': return 'status-pending';
        case 'left': return 'status-left';
        default: return '';
    }
}

async function loadServers() {
    try {
        const response = await apiCall('/admin/api/irc/servers');
        servers = response.data || [];
        renderServers();
    } catch (err) {
        showAlert('Failed to load servers: ' + err.message);
    }
}

function renderServers() {
    const container = document.getElementById('serversList');
    
    if (servers.length === 0) {
        container.innerHTML = '<div class="empty">No IRC servers configured. Click "Add Server" to create one.</div>';
        return;
    }
    
    container.innerHTML = servers.map(server => {
        const serverChannels = server.channels || [];
        return `
            <div class="server-card">
                <div class="server-card-header">
                    <h3>${escapeHtml(server.name)}</h3>
                    <div class="actions">
                        <span class="status-badge ${getStatusClass(server.status)}">${escapeHtml(server.status)}</span>
                        <button class="btn sm secondary" data-action="connect-server" data-min-role="operator" data-id="${server.id}">Connect</button>
                        <button class="btn sm secondary" data-action="disconnect-server" data-min-role="operator" data-id="${server.id}">Disconnect</button>
                        <button class="btn sm secondary" data-action="edit-server" data-min-role="admin" data-id="${server.id}">Edit</button>
                        <button class="btn sm danger" data-action="delete-server" data-min-role="admin" data-id="${server.id}">Delete</button>
                    </div>
                </div>
                <div class="server-info">
                    <div><span>Host:</span> ${escapeHtml(server.server_host)}:${server.server_port}</div>
                    <div><span>Nick:</span> ${escapeHtml(server.nick)}</div>
                    <div><span>TLS:</span> ${server.use_tls ? 'Yes' : 'No'}</div>
                </div>
                ${serverChannels.length > 0 ? `
                    <div class="channel-list">
                        <strong>Channels:</strong>
                        ${serverChannels.map(ch => `<span class="channel-tag">${escapeHtml(ch.channel_name)} <span class="status-badge ${getStatusClass(ch.status)}">${escapeHtml(ch.status)}</span></span>`).join('')}
                    </div>
                ` : ''}
                ${server.last_error ? `<div style="color: var(--fwmon-sig-crit); margin-top: 10px; font-size: 0.85rem;">Error: ${escapeHtml(server.last_error)}</div>` : ''}
            </div>
        `;
    }).join('');
}

function openServerModal(server = null) {
    AdminCommon.openModal('serverModal');
    document.getElementById('serverModalTitle').textContent = server ? 'Edit Server' : 'Add Server';
    document.getElementById('serverId').value = server ? server.id : '';
    document.getElementById('serverName').value = server ? server.name : '';
    document.getElementById('serverHost').value = server ? server.server_host : '';
    document.getElementById('serverPort').value = server ? server.server_port : 6667;
    document.getElementById('serverNick').value = server ? server.nick : '';
    document.getElementById('serverUsername').value = server ? server.username : '';
    document.getElementById('serverRealName').value = server ? server.real_name : '';
    document.getElementById('serverPassword').value = '';
    document.getElementById('serverNickServPassword').value = '';
    document.getElementById('serverNickServIdentify').checked = server ? server.nickserv_identify : false;
    document.getElementById('serverUseTLS').checked = server ? server.use_tls : false;
    document.getElementById('serverSASLEnabled').checked = server ? server.sasl_enabled : false;
    document.getElementById('serverSASLUsername').value = server ? server.sasl_username : '';
    document.getElementById('serverSASLPassword').value = '';
    document.getElementById('serverEnabled').checked = server ? server.enabled : true;
    document.getElementById('serverAutoReconnect').checked = server ? server.auto_reconnect : true;
    toggleSASLFields();
}

function closeServerModal() {
    AdminCommon.closeModal('serverModal');
}

function toggleSASLFields() {
    // v0.10.231: the markup has class="hidden" so this previously worked
    // only because inline style.display beats class specificity. The
    // moment anyone refactored to style.display='' (the v0.10.230 footgun)
    // the field would silently disappear and stop responding to the
    // checkbox. Toggle the .hidden class directly so the markup's initial
    // state and the JS toggling agree on a single source of truth.
    const saslEnabled = document.getElementById('serverSASLEnabled').checked;
    document.getElementById('saslFields').classList.toggle('hidden', !saslEnabled);
}

document.getElementById('serverSASLEnabled').addEventListener('change', toggleSASLFields);

async function saveServer(e) {
    e.preventDefault();
    
    const serverData = {
        name: document.getElementById('serverName').value,
        server_host: document.getElementById('serverHost').value,
        server_port: parseInt(document.getElementById('serverPort').value),
        nick: document.getElementById('serverNick').value,
        username: document.getElementById('serverUsername').value,
        real_name: document.getElementById('serverRealName').value,
        server_password: document.getElementById('serverPassword').value,
        nickserv_password: document.getElementById('serverNickServPassword').value,
        nickserv_identify: document.getElementById('serverNickServIdentify').checked,
        use_tls: document.getElementById('serverUseTLS').checked,
        sasl_enabled: document.getElementById('serverSASLEnabled').checked,
        sasl_username: document.getElementById('serverSASLUsername').value,
        sasl_password: document.getElementById('serverSASLPassword').value,
        enabled: document.getElementById('serverEnabled').checked,
        auto_reconnect: document.getElementById('serverAutoReconnect').checked
    };
    
    const id = document.getElementById('serverId').value;
    const url = id ? `/admin/api/irc/servers/${id}` : '/admin/api/irc/servers';
    const method = id ? 'PUT' : 'POST';
    
    try {
        await apiCall(url, {
            method: method,
            body: JSON.stringify(serverData)
        });
        closeServerModal();
        loadServers();
        showAlert('Server saved successfully', false);
    } catch (err) {
        showAlert('Failed to save server: ' + err.message);
    }
}

function editServer(id) {
    const server = servers.find(s => s.id === id);
    if (server) openServerModal(server);
}

async function deleteServer(id) {
    const ok = await AdminCommon.confirm('Are you sure you want to delete this server?', {
        title: 'Delete IRC server?',
        confirmLabel: 'Delete',
        danger: true,
    });
    if (!ok) return;

    try {
        await apiCall(`/admin/api/irc/servers/${id}`, { method: 'DELETE' });
        loadServers();
        showAlert('Server deleted', false);
    } catch (err) {
        showAlert('Failed to delete server: ' + err.message);
    }
}

async function connectServer(id) {
    try {
        await apiCall(`/admin/api/irc/servers/${id}/connect`, { method: 'POST' });
        showAlert('Connecting to server...', false);
        setTimeout(loadServers, 2000);
    } catch (err) {
        showAlert('Failed to connect: ' + err.message);
    }
}

async function disconnectServer(id) {
    try {
        await apiCall(`/admin/api/irc/servers/${id}/disconnect`, { method: 'POST' });
        loadServers();
        showAlert('Disconnected', false);
    } catch (err) {
        showAlert('Failed to disconnect: ' + err.message);
    }
}

async function testServer() {
    const testData = {
        server_host: document.getElementById('serverHost').value,
        server_port: parseInt(document.getElementById('serverPort').value),
        nick: document.getElementById('serverNick').value,
        username: document.getElementById('serverUsername').value,
        server_password: document.getElementById('serverPassword').value,
        use_tls: document.getElementById('serverUseTLS').checked,
        sasl_enabled: document.getElementById('serverSASLEnabled').checked,
        sasl_username: document.getElementById('serverSASLUsername').value,
        sasl_password: document.getElementById('serverSASLPassword').value
    };
    
    try {
        const response = await apiCall('/admin/api/irc/servers/test', {
            method: 'POST',
            body: JSON.stringify(testData)
        });
        if (response.data.success) {
            showAlert('Connection successful!', false);
        } else {
            showAlert('Connection failed: ' + response.data.message);
        }
    } catch (err) {
        showAlert('Test failed: ' + err.message);
    }
}

async function loadChannels() {
    try {
        const response = await apiCall('/admin/api/irc/channels');
        channels = response.data || [];
        renderChannels();
    } catch (err) {
        showAlert('Failed to load channels: ' + err.message);
    }
}

function renderChannels() {
    const container = document.getElementById('channelsList');
    
    if (channels.length === 0) {
        container.innerHTML = '<div class="empty">No channels configured. Click "Add Channel" to create one.</div>';
        return;
    }
    
    container.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>Channel</th>
                    <th>Server</th>
                    <th>Auto Join</th>
                    <th>Send Alerts</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${channels.map(ch => {
                    const server = servers.find(s => s.id === ch.server_id);
                    return `
                        <tr>
                            <td>${escapeHtml(ch.channel_name)}</td>
                            <td>${server ? escapeHtml(server.name) : 'Unknown'}</td>
                            <td>${ch.auto_join ? 'Yes' : 'No'}</td>
                            <td>${ch.send_alerts ? 'Yes' : 'No'}</td>
                            <td><span class="status-badge ${getStatusClass(ch.status)}">${escapeHtml(ch.status)}</span></td>
                            <td>
                                <div class="actions">
                                    <button class="btn sm secondary" data-action="edit-channel" data-min-role="admin" data-id="${ch.id}">Edit</button>
                                    <button class="btn sm danger" data-action="delete-channel" data-min-role="admin" data-id="${ch.id}">Delete</button>
                                </div>
                            </td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
}

function openServerSelect() {
    const select = document.getElementById('channelServerId');
    select.innerHTML = '<option value="">Select a server...</option>' +
        servers.map(s => `<option value="${s.id}">${escapeHtml(s.name)}</option>`).join('');
}

function openChannelModal(channel = null) {
    openServerSelect();
    AdminCommon.openModal('channelModal');
    document.getElementById('channelModalTitle').textContent = channel ? 'Edit Channel' : 'Add Channel';
    document.getElementById('channelId').value = channel ? channel.id : '';
    document.getElementById('channelServerId').value = channel ? channel.server_id : '';
    document.getElementById('channelName').value = channel ? channel.channel_name : '';
    document.getElementById('channelKey').value = '';
    document.getElementById('channelChanServName').value = channel ? channel.chanserv_name : '';
    document.getElementById('channelChanServPass').value = '';
    document.getElementById('channelAutoJoin').checked = channel ? channel.auto_join : true;
    document.getElementById('channelSendAlerts').checked = channel ? channel.send_alerts : false;
    document.getElementById('channelSendStatus').checked = channel ? channel.send_status : false;
    document.getElementById('channelStatusInterval').value = channel ? Math.round((channel.status_interval || 300) / 60) : 5;
    document.getElementById('channelEnabled').checked = channel ? channel.enabled : true;
    toggleStatusInterval();
}

function closeChannelModal() {
    AdminCommon.closeModal('channelModal');
}

function toggleStatusInterval() {
    // v0.10.231: same .hidden-trap fix as toggleSASLFields. The element
    // carries class="hidden" in markup; toggle that class directly rather
    // than fighting it with inline style.
    const checked = document.getElementById('channelSendStatus').checked;
    document.getElementById('statusIntervalGroup').classList.toggle('hidden', !checked);
}

async function saveChannel(e) {
    e.preventDefault();
    
    const channelData = {
        server_id: parseInt(document.getElementById('channelServerId').value),
        channel_name: document.getElementById('channelName').value,
        channel_key: document.getElementById('channelKey').value,
        chanserv_name: document.getElementById('channelChanServName').value,
        chanserv_password: document.getElementById('channelChanServPass').value,
        auto_join: document.getElementById('channelAutoJoin').checked,
        send_alerts: document.getElementById('channelSendAlerts').checked,
        send_status: document.getElementById('channelSendStatus').checked,
        status_interval: parseInt(document.getElementById('channelStatusInterval').value || '5') * 60,
        enabled: document.getElementById('channelEnabled').checked
    };
    
    const id = document.getElementById('channelId').value;
    const url = id ? `/admin/api/irc/channels/${id}` : '/admin/api/irc/channels';
    const method = id ? 'PUT' : 'POST';
    
    try {
        await apiCall(url, {
            method: method,
            body: JSON.stringify(channelData)
        });
        closeChannelModal();
        loadChannels();
        showAlert('Channel saved successfully', false);
    } catch (err) {
        showAlert('Failed to save channel: ' + err.message);
    }
}

function editChannel(id) {
    const channel = channels.find(c => c.id === id);
    if (channel) openChannelModal(channel);
}

async function deleteChannel(id) {
    const ok = await AdminCommon.confirm('Are you sure you want to delete this channel?', {
        title: 'Delete IRC channel?',
        confirmLabel: 'Delete',
        danger: true,
    });
    if (!ok) return;

    try {
        await apiCall(`/admin/api/irc/channels/${id}`, { method: 'DELETE' });
        loadChannels();
        showAlert('Channel deleted', false);
    } catch (err) {
        showAlert('Failed to delete channel: ' + err.message);
    }
}

async function loadCommands() {
    try {
        const response = await apiCall('/admin/api/irc/commands');
        commands = response.data || [];
        renderCommands();
    } catch (err) {
        showAlert('Failed to load commands: ' + err.message);
    }
}

function renderCommands() {
    const container = document.getElementById('commandsList');
    
    if (commands.length === 0) {
        container.innerHTML = '<tr><td colspan="6" class="empty">No custom commands. Click "Add Command" to create one.</td></tr>';
        return;
    }
    
    container.innerHTML = commands.map(cmd => `
        <tr>
            <td><code>${escapeHtml(cmd.command)}</code></td>
            <td>${escapeHtml(cmd.description)}</td>
            <td>${escapeHtml(cmd.command_type)}</td>
            <td>${cmd.admin_only ? 'Yes' : 'No'}</td>
            <td>${cmd.enabled ? 'Yes' : 'No'}</td>
            <td>
                <div class="actions">
                    <button class="btn sm secondary" data-action="edit-command" data-min-role="operator" data-id="${cmd.id}">Edit</button>
                    <button class="btn sm danger" data-action="delete-command" data-min-role="operator" data-id="${cmd.id}">Delete</button>
                </div>
            </td>
        </tr>
    `).join('');
}

function openCommandModal(command = null) {
    AdminCommon.openModal('commandModal');
    document.getElementById('commandModalTitle').textContent = command ? 'Edit Command' : 'Add Command';
    document.getElementById('commandId').value = command ? command.id : '';
    document.getElementById('commandCmd').value = command ? command.command : '';
    document.getElementById('commandDescription').value = command ? command.description : '';
    document.getElementById('commandType').value = command ? command.command_type : 'static';
    document.getElementById('commandResponse').value = command ? command.response : '';
    document.getElementById('commandAdminOnly').checked = command ? command.admin_only : false;
    document.getElementById('commandEnabled').checked = command ? command.enabled : true;
    toggleCommandResponse();
}

function closeCommandModal() {
    AdminCommon.closeModal('commandModal');
}

function toggleCommandResponse() {
    const type = document.getElementById('commandType').value;
    const responseField = document.getElementById('responseField');
    responseField.style.display = type === 'static' || type === 'custom' ? 'block' : 'none';
}

document.getElementById('commandType').addEventListener('change', toggleCommandResponse);
document.getElementById('channelSendStatus').addEventListener('change', toggleStatusInterval);
document.getElementById('sendServerSelect').addEventListener('change', loadChannelsForSend);

// Form submit listeners
document.getElementById('serverForm').addEventListener('submit', saveServer);
document.getElementById('channelForm').addEventListener('submit', saveChannel);
document.getElementById('commandForm').addEventListener('submit', saveCommand);

// Event delegation for data-action buttons and tabs
document.addEventListener('click', function(e) {
    var btn = e.target.closest('[data-action],[data-tab]');
    if (!btn) return;

    var tab = btn.getAttribute('data-tab');
    if (tab) {
        switchTab(tab, btn);
        return;
    }

    var action = btn.getAttribute('data-action');
    var id = btn.getAttribute('data-id');
    if (id) id = parseInt(id, 10);

    switch (action) {
        // AUDIT-047: the IRC page's delegated switch had no logout case, so
        // the sidebar "Logout" link (data-action="logout") was dead — it
        // navigated to '#' and stayed on the page. This file uses the full
        // AdminCommon reference (no AC alias is defined here).
        case 'logout': AdminCommon.doLogout(); return;
        case 'open-server-modal': openServerModal(); break;
        case 'close-server-modal': closeServerModal(); break;
        case 'test-server': testServer(); break;
        case 'open-channel-modal': openChannelModal(); break;
        case 'close-channel-modal': closeChannelModal(); break;
        case 'open-command-modal': openCommandModal(); break;
        case 'close-command-modal': closeCommandModal(); break;
        case 'send-message': sendMessage(); break;
        case 'connect-server': connectServer(id); break;
        case 'disconnect-server': disconnectServer(id); break;
        case 'edit-server': editServer(id); break;
        case 'delete-server': deleteServer(id); break;
        case 'edit-channel': editChannel(id); break;
        case 'delete-channel': deleteChannel(id); break;
        case 'edit-command': editCommand(id); break;
        case 'delete-command': deleteCommand(id); break;
    }
});

async function saveCommand(e) {
    e.preventDefault();
    
    const commandData = {
        command: document.getElementById('commandCmd').value,
        description: document.getElementById('commandDescription').value,
        command_type: document.getElementById('commandType').value,
        response: document.getElementById('commandResponse').value,
        admin_only: document.getElementById('commandAdminOnly').checked,
        enabled: document.getElementById('commandEnabled').checked
    };
    
    const id = document.getElementById('commandId').value;
    const url = id ? `/admin/api/irc/commands/${id}` : '/admin/api/irc/commands';
    const method = id ? 'PUT' : 'POST';
    
    try {
        await apiCall(url, {
            method: method,
            body: JSON.stringify(commandData)
        });
        closeCommandModal();
        loadCommands();
        showAlert('Command saved successfully', false);
    } catch (err) {
        showAlert('Failed to save command: ' + err.message);
    }
}

function editCommand(id) {
    const command = commands.find(c => c.id === id);
    if (command) openCommandModal(command);
}

async function deleteCommand(id) {
    const ok = await AdminCommon.confirm('Are you sure you want to delete this command?', {
        title: 'Delete IRC command?',
        confirmLabel: 'Delete',
        danger: true,
    });
    if (!ok) return;

    try {
        await apiCall(`/admin/api/irc/commands/${id}`, { method: 'DELETE' });
        loadCommands();
        showAlert('Command deleted', false);
    } catch (err) {
        showAlert('Failed to delete command: ' + err.message);
    }
}

async function loadServersForSend() {
    try {
        const response = await apiCall('/admin/api/irc/servers');
        servers = response.data || [];
        
        const select = document.getElementById('sendServerSelect');
        select.innerHTML = '<option value="">Select a server...</option>' +
            servers.filter(s => s.status === 'connected').map(s => 
                `<option value="${s.id}">${escapeHtml(s.name)}</option>`
            ).join('');
    } catch (err) {
        showAlert('Failed to load servers: ' + err.message);
    }
}

async function loadChannelsForSend() {
    const serverId = document.getElementById('sendServerSelect').value;
    const channelSelect = document.getElementById('sendChannelSelect');
    
    if (!serverId) {
        channelSelect.innerHTML = '<option value="">Select a channel...</option>';
        return;
    }
    
    try {
        const response = await apiCall(`/admin/api/irc/channels?server_id=${serverId}`);
        const serverChannels = response.data || [];
        
        channelSelect.innerHTML = '<option value="">Select a channel...</option>' +
            serverChannels.filter(c => c.status === 'joined').map(c => 
                `<option value="${escapeHtml(c.channel_name)}">${escapeHtml(c.channel_name)}</option>`
            ).join('');
    } catch (err) {
        showAlert('Failed to load channels: ' + err.message);
    }
}

async function sendMessage() {
    const serverId = document.getElementById('sendServerSelect').value;
    const channel = document.getElementById('sendChannelSelect').value;
    const message = document.getElementById('sendMessage').value;
    
    if (!serverId || !channel || !message) {
        showAlert('Please fill in all fields');
        return;
    }
    
    try {
        await apiCall('/admin/api/irc/send', {
            method: 'POST',
            body: JSON.stringify({
                server_id: parseInt(serverId),
                channel: channel,
                message: message
            })
        });
        document.getElementById('sendMessage').value = '';
        showAlert('Message sent!', false);
    } catch (err) {
        showAlert('Failed to send message: ' + err.message);
    }
}

function escapeHtml(text) {
    // AUDIT-059: nullish check, not falsy — `if (!text)` blanked numeric 0.
    // AUDIT F2: use the replace-chain (not the textContent→innerHTML trick),
    // which ALSO escapes " and ' — required for the <option value="..."> sink
    // below, where the textContent form left quotes unescaped (a channel name
    // like `" onmouseover=...` could break out of the value attribute).
    if (text == null) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Init — the SPA calls this when the IRC page is shown (admin-main.js
// loadPageData). The click delegation + change-listeners above run once at
// module load; only the data fetch is deferred.
window.FwmonIrc = { init: function () { loadServers(); } };

})(); // AUDIT-050: end IIFE
