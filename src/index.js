export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
}

// 主请求处理器
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;

  const LINKS = {
    get: async (key) => await env.LINKS.get(key),
    put: async (key, value) => await env.LINKS.put(key, value),
    delete: async (key) => await env.LINKS.delete(key)
  };

  // 处理OPTIONS预检请求
  if (request.method === 'OPTIONS') {
    return createCorsResponse();
  }

  try {
    switch (path) {
      case '/api/login':
        return handleLogin(request, env);
      case '/api/links':
        return handleLinksRequest(request, env, ctx, LINKS);
      case '/api/links/bulk':
        return handleBulkAddRequest(request, env, LINKS);
      case '/api/validate':
        return handleValidateToken(request, env);
      case '/api/clear-cache':
        return handleClearCache(request, env, LINKS);
      default:
        return createJsonResponse({ error: 'Not Found' }, 404);
    }
  } catch (err) {
    console.error('Error:', err);
    return createJsonResponse({ error: 'Internal server error' }, 500);
  }
}

// 批量添加链接
async function handleBulkAddLinks(request, LINKS) {
  const linksToAdd = await request.json();

  if (!Array.isArray(linksToAdd)) {
    return createJsonResponse({ error: 'Expected an array of links' }, 400);
  }

  const currentLinks = await getLinksFromKV(LINKS);

  const newLinks = linksToAdd.map(link => ({
    id: Date.now().toString() + Math.random().toString(36).slice(2), // 避免重复
    name: link.name?.trim() || 'Unnamed',
    url: link.url?.trim() || '',
    category: link.category?.trim() || 'default',
    icon: link.icon?.trim() || '',
    createdAt: new Date().toISOString()
  }));

  const updatedLinks = currentLinks.concat(newLinks);

  await LINKS.put('links', JSON.stringify(updatedLinks));

  return createJsonResponse({ success: true, added: newLinks.length });
}

async function handleBulkAddRequest(request, env, LINKS) {
  if (request.method !== 'POST') {
    return createJsonResponse({ error: 'Method not allowed' }, 405);
  }

  const authResult = await verifyAdmin(request, env);
  if (!authResult.valid) {
    return createJsonResponse({ error: 'Unauthorized' }, 401);
  }

  return handleBulkAddLinks(request, LINKS);
}




// 路由处理器
async function handleLinksRequest(request, env, ctx, LINKS) {
  if (request.method === 'GET') {
    return handleGetLinks(request, ctx, LINKS);
  }

  const authResult = await verifyAdmin(request, env);
  if (!authResult.valid) {
    return createJsonResponse({ error: 'Unauthorized' }, 401);
  }

  switch (request.method) {
    case 'POST':
      return handleAddLink(request, LINKS);
    case 'PUT':
      return handleUpdateLink(request, LINKS);
    case 'DELETE':
      return handleDeleteLink(request, LINKS);
    default:
      return createJsonResponse({ error: 'Method not allowed' }, 405);
  }
}

// 获取链接 (带缓存)
async function handleGetLinks(request, ctx, LINKS) {
  // 检查是否有强制刷新参数
  const url = new URL(request.url);
  const forceRefresh = url.searchParams.has('refresh');
  
  const cache = caches.default;
  const cacheKey = new Request(request.url, request);

  // 如果有强制刷新参数，跳过缓存检查
  if (!forceRefresh) {
    const cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      const response = new Response(cachedResponse.body, cachedResponse);
      response.headers.set('X-Cache', 'HIT');
      return addCorsHeaders(response);
    }
  }

  // 从KV获取最新数据
  const links = await getLinksFromKV(LINKS);
  const response = createJsonResponse(links);
  response.headers.set('X-Cache', 'MISS');
  
  // 更新缓存
  ctx.waitUntil(cache.put(cacheKey, response.clone()));
  
  return response;
}

// 添加链接
async function handleAddLink(request, LINKS) {
  const data = await request.json();
  if (!data.name || !data.url) {
    return createJsonResponse({ error: 'Missing required fields' }, 400);
  }

  const newLink = {
    id: Date.now().toString(),
    name: data.name.trim(),
    url: data.url.trim(),
    category: data.category?.trim() || 'default',
    icon: data.icon?.trim() || '',
    createdAt: new Date().toISOString()
  };

  await addLinkToKV(LINKS, newLink);
  return createJsonResponse({ success: true, id: newLink.id });
}


// 删除链接
async function handleDeleteLink(request, LINKS) {
  try {
    const url = new URL(request.url);
    const id = url.searchParams.get('id');
    
    if (!id) {
      return createJsonResponse({ error: 'Missing link ID parameter' }, 400);
    }

    // 获取当前所有链接
    const links = await getLinksFromKV(LINKS);
    
    // 查找要删除的链接索引
    const linkIndex = links.findIndex(link => link.id === id);
    
    if (linkIndex === -1) {
      return createJsonResponse({ error: 'Link not found' }, 404);
    }

    // 删除链接
    links.splice(linkIndex, 1);
    
    // 更新KV存储
    await LINKS.put('links', JSON.stringify(links));
    
    // 返回成功响应
    return createJsonResponse({ 
      success: true,
      message: 'Link deleted successfully',
      deletedId: id
    });
    
  } catch (err) {
    console.error('Delete link error:', err);
    return createJsonResponse({ 
      error: 'Failed to delete link',
      details: err.message 
    }, 500);
  }
}

// 登录处理
async function handleLogin(request, env) {
  if (request.method !== 'POST') {
    return createJsonResponse({ error: 'Method not allowed' }, 405);
  }

  try {
    const { username, password } = await request.json();
    const ADMIN_USERNAME = env.ADMIN_USERNAME;
    const ADMIN_PASSWORD = env.ADMIN_PASSWORD;

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      const JWT_SECRET = env.JWT_SECRET;
      const token = await createJWT({ username, role: 'admin' }, JWT_SECRET);
      return createJsonResponse({ token });
    }

    return createJsonResponse({ error: 'Invalid credentials' }, 401);
  } catch (err) {
    console.error('Login error:', err);
    return createJsonResponse({ error: 'Internal server error' }, 500);
  }
}

// JWT 创建与验证
async function createJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify({
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400 // 24小时
  }));

  const signature = await crypto.subtle.sign(
    { name: 'HMAC', hash: 'SHA-256' },
    await getSigningKey(secret),
    new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`)
  );

  return `${encodedHeader}.${encodedPayload}.${base64url(signature)}`;
}

async function verifyAdmin(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { valid: false };
  }

  const token = authHeader.split(' ')[1];
  const [header, payload, signature] = token.split('.');

  const JWT_SECRET = env.JWT_SECRET;
  const isValid = await crypto.subtle.verify(
    { name: 'HMAC', hash: 'SHA-256' },
    await getSigningKey(JWT_SECRET),
    base64urlToArrayBuffer(signature),
    new TextEncoder().encode(`${header}.${payload}`)
  );

  if (!isValid) return { valid: false };

  const decodedPayload = JSON.parse(atob(payload));
  if (decodedPayload.exp < Date.now() / 1000) return { valid: false };
  if (decodedPayload.role !== 'admin') return { valid: false };

  return { valid: true, payload: decodedPayload };
}

async function getSigningKey(secret) {
  return await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

// 辅助操作
async function getLinksFromKV(LINKS) {
  const data = await LINKS.get('links');
  return data ? JSON.parse(data) : [];
}

async function addLinkToKV(LINKS, newLink) {
  const links = await getLinksFromKV(LINKS);
  links.push(newLink);
  await LINKS.put('links', JSON.stringify(links));
}

// 其他 API 路由
async function handleValidateToken(request, env) {
  const authResult = await verifyAdmin(request, env);
  return createJsonResponse({ valid: authResult.valid });
}

async function handleClearCache(request, env, LINKS) {
  const authResult = await verifyAdmin(request, env);
  if (!authResult.valid) {
    return createJsonResponse({ error: 'Unauthorized' }, 401);
  }

  await LINKS.delete('links');
  return createJsonResponse({ success: true });
}

// 响应助手
function createJsonResponse(data, status = 200) {
  const response = new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json'
    }
  });
  return addCorsHeaders(response);
}

function createCorsResponse() {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    }
  });
}

function addCorsHeaders(response) {
  response.headers.set('Access-Control-Allow-Origin', '*');
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return response;
}

function base64url(input) {
  const str = typeof input === 'string' ? btoa(input) : btoa(String.fromCharCode(...new Uint8Array(input)));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToArrayBuffer(base64url) {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}