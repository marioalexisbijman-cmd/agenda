export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  try {
    const {
      SUPABASE_URL,
      SUPABASE_ANON_KEY,
      SUPABASE_SERVICE_ROLE_KEY,
      MASTER_ADMIN_EMAIL
    } = process.env;

    if (
      !SUPABASE_URL ||
      !SUPABASE_ANON_KEY ||
      !SUPABASE_SERVICE_ROLE_KEY ||
      !MASTER_ADMIN_EMAIL
    ) {
      return res.status(500).json({
        error: 'Faltan variables de entorno del servidor.'
      });
    }

    const authHeader = req.headers.authorization || '';

    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Sesión de administrador no válida.'
      });
    }

    const accessToken = authHeader.substring(7);

    // 1. Comprobar quién está realizando la operación
    const userResponse = await fetch(
      `${SUPABASE_URL}/auth/v1/user`,
      {
        headers: {
          apikey: SUPABASE_ANON_KEY,
          Authorization: `Bearer ${accessToken}`
        }
      }
    );

    if (!userResponse.ok) {
      return res.status(401).json({
        error: 'No fue posible verificar la sesión.'
      });
    }

    const adminUser = await userResponse.json();

    if (
      !adminUser.email ||
      adminUser.email.toLowerCase() !== MASTER_ADMIN_EMAIL.toLowerCase()
    ) {
      return res.status(403).json({
        error: 'Solo el Administrador Maestro puede realizar esta operación.'
      });
    }

    const { email, temporaryPassword } = req.body || {};

    if (!email || !temporaryPassword) {
      return res.status(400).json({
        error: 'Debes indicar correo y clave temporal.'
      });
    }

    if (temporaryPassword.length < 8) {
      return res.status(400).json({
        error: 'La clave temporal debe tener al menos 8 caracteres.'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // 2. Buscar al profesional en Supabase Authentication
    const listResponse = await fetch(
      `${SUPABASE_URL}/auth/v1/admin/users?per_page=1000`,
      {
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
        }
      }
    );

    if (!listResponse.ok) {
      const detail = await listResponse.text();
      return res.status(500).json({
        error: 'No fue posible consultar los usuarios.',
        detail
      });
    }

    const usersData = await listResponse.json();

    const users = Array.isArray(usersData)
      ? usersData
      : (usersData.users || []);

    const professional = users.find(
      user =>
        (user.email || '').trim().toLowerCase() === normalizedEmail
    );

    if (!professional) {
      return res.status(404).json({
        error: 'El profesional no existe en Authentication.'
      });
    }

    // 3. Asignar clave temporal y exigir cambio al primer ingreso
    const existingMetadata = professional.user_metadata || {};

    const updateResponse = await fetch(
      `${SUPABASE_URL}/auth/v1/admin/users/${professional.id}`,
      {
        method: 'PUT',
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          password: temporaryPassword,
          user_metadata: {
            ...existingMetadata,
            must_change_password: true
          }
        })
      }
    );

    if (!updateResponse.ok) {
      const detail = await updateResponse.text();
      return res.status(500).json({
        error: 'No fue posible asignar la clave temporal.',
        detail
      });
    }

    return res.status(200).json({
      ok: true,
      message: 'Clave temporal asignada correctamente.'
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: 'Error interno del servidor.'
    });
  }
}
