const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const app = express();
app.use(cors({ origin: '*' }));
app.use(bodyParser.json());

const JWT_SECRET = 'gk_demo_secure_key_2026';

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (!err) {
                req.user = user;
            }
        });
    }
    next();
};

app.use(authenticateToken);

app.get('/', (req, res) => {
    res.send('✅ Gatekeeper API is Working! (Vercel Ready)');
});

app.post('/api/login', async (req, res) => {
    const { userId, password } = req.body;
    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
        if (rows.length === 0) return res.status(401).json({ success: false, message: 'User not found' });

        const user = rows[0];
        
        let isMatch = false;
        if (user.password && user.password.startsWith('$2a$')) {
            isMatch = await bcrypt.compare(password, user.password);
        } else {
            isMatch = (password === user.password);
        }

        if (isMatch) {
            const token = jwt.sign({ id: user.id, role: user.role, societyId: user.assigned_society_id }, JWT_SECRET, { expiresIn: '24h' });
            res.json({ success: true, token, user });
        } else {
            res.status(401).json({ success: false, message: 'Invalid Password' });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/hash-password', async (req, res) => {
    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(req.body.password, salt);
    res.json({ hashed });
});

app.get('/api/societies', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM societies');
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/buildings/:societyId', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM buildings WHERE society_id = ?', [req.params.societyId]);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/buildings', async (req, res) => {
    const { id, societyId, name, type } = req.body;
    try {
        await pool.query('INSERT INTO buildings (id, society_id, name, type) VALUES (?, ?, ?, ?)', [id, societyId, name, type]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/flats/:buildingId', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, number, owner_name FROM flats WHERE building_id = ? ORDER BY number ASC', [req.params.buildingId]);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/:societyId', async (req, res) => {
    const { role } = req.query; 
    const { societyId } = req.params;
    
    try {
        let query = `
            SELECT u.*, 
                   GROUP_CONCAT(sb.building_id) as assigned_buildings,
                   p.view_only, p.assign_shifts, p.create_gatekeeper, p.add_watchman
            FROM users u
            LEFT JOIN supervisor_buildings sb ON u.id = sb.supervisor_id
            LEFT JOIN permissions p ON u.id = p.user_id
            WHERE u.assigned_society_id = ?
        `;
        const params = [societyId];

        if (role) {
            query += ' AND u.role = ?';
            params.push(role);
        }
        
        query += ' GROUP BY u.id';
        
        const [rows] = await pool.query(query, params);
        
        const formatted = rows.map(u => ({
            ...u,
            assignedBuildingIds: u.assigned_buildings ? u.assigned_buildings.split(',') : [],
            permissions: {
                viewOnly: !!u.view_only,
                assignShifts: !!u.assign_shifts,
                createGatekeeper: !!u.create_gatekeeper,
                addWatchman: !!u.add_watchman
            }
        }));

        res.json(formatted);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users/save', async (req, res) => {
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();

        const { 
            id, role, name, phone, password, societyId, 
            shift, assignedBuildingIds, permissions, 
            gateId, checkoutRequired, isEdit 
        } = req.body;

        let query = '';
        let params = [];
        let passwordClause = '';

        if (password && password.trim() !== '') {
            const salt = await bcrypt.genSalt(10);
            const hashed = await bcrypt.hash(password, salt);
            passwordClause = `, password = '${hashed}'`;
        }

        if (isEdit) {
            query = `UPDATE users SET name=?, phone=?, shift=?, current_shift=?, assigned_building_id=?, checkout_required=? ${passwordClause} WHERE id=?`;
            params = [name, phone, shift || 'Morning', shift || 'Morning', gateId || null, checkoutRequired ? 1 : 0, id];
        } else {
            const newId = id || (role.substring(0, 3).toUpperCase() + Date.now().toString().slice(-6));
            const salt = await bcrypt.genSalt(10);
            const hashed = await bcrypt.hash(password || '123456', salt); 

            query = `INSERT INTO users (id, role, name, phone, password, assigned_society_id, shift, current_shift, assigned_building_id, checkout_required, is_online) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
            params = [newId, role, name, phone, hashed, societyId, shift || 'Morning', shift || 'Morning', gateId || null, checkoutRequired ? 1 : 0, 0];
        }

        await connection.query(query, params);
        const targetId = isEdit ? id : params[0];

        if (role === 'SUPERVISOR') {
            if (permissions) {
                await connection.query('DELETE FROM permissions WHERE user_id = ?', [targetId]);
                await connection.query(
                    `INSERT INTO permissions (user_id, view_only, assign_shifts, create_gatekeeper, add_watchman) VALUES (?, ?, ?, ?, ?)`,
                    [targetId, permissions.viewOnly, permissions.assignShifts, permissions.createGatekeeper, permissions.addWatchman]
                );
            }

            if (assignedBuildingIds && Array.isArray(assignedBuildingIds)) {
                await connection.query('DELETE FROM supervisor_buildings WHERE supervisor_id = ?', [targetId]);
                if (assignedBuildingIds.length > 0) {
                    const buildingValues = assignedBuildingIds.map(bid => [targetId, bid]);
                    await connection.query('INSERT INTO supervisor_buildings (supervisor_id, building_id) VALUES ?', [buildingValues]);
                }
            }
        }

        await connection.commit();
        res.json({ success: true, userId: targetId });

    } catch (e) {
        await connection.rollback();
        console.error(e);
        res.status(500).json({ success: false, error: e.message });
    } finally {
        connection.release();
    }
});

app.delete('/api/users/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/visitor/entry', async (req, res) => {
    const { 
        gatekeeperId, visitorName, visitorType, visitorPhone, 
        photoUrl, visitingBuildingId, visitingFlat, guestCount, allowedTime 
    } = req.body;

    const logId = 'L' + Date.now(); 

    try {
        await pool.query(
            `INSERT INTO visitor_logs 
            (log_id, gatekeeper_id, visitor_name, visitor_type, visitor_phone, photo_url, visiting_building_id, visiting_flat, guest_count, allowed_time_minutes, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'INSIDE')`,
            [logId, gatekeeperId, visitorName, visitorType, visitorPhone, photoUrl, visitingBuildingId, visitingFlat, guestCount || 1, allowedTime || null]
        );
        res.json({ success: true, logId });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/dashboard/stats/:buildingId', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT 
                COUNT(*) as total_entries,
                SUM(CASE WHEN l.status = 'INSIDE' THEN 1 ELSE 0 END) as inside_now,
                SUM(CASE WHEN l.status = 'EXITED' THEN 1 ELSE 0 END) as exited_total,
                SUM(CASE WHEN l.status = 'INSIDE' AND l.allowed_time_minutes IS NOT NULL AND TIMESTAMPDIFF(MINUTE, l.entry_time, NOW()) > l.allowed_time_minutes THEN 1 ELSE 0 END) as overdue_count
            FROM visitor_logs l
            JOIN buildings b ON l.visiting_building_id = b.id
            WHERE b.society_id = (SELECT society_id FROM buildings WHERE id = ?) 
            AND DATE(l.entry_time) = CURDATE()
        `, [req.params.buildingId]);
        res.json(rows[0]);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/visitor/logs/:buildingId', async (req, res) => {
    try {
        const [rows] = await pool.query(
            `SELECT l.*, b.name as building_name 
             FROM visitor_logs l
             JOIN buildings b ON l.visiting_building_id = b.id
             WHERE b.society_id = (SELECT society_id FROM buildings WHERE id = ?) 
             ORDER BY l.entry_time DESC LIMIT 100`,
            [req.params.buildingId]
        );
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/visitor/checkout', async (req, res) => {
    try {
        await pool.query("UPDATE visitor_logs SET status = 'EXITED', exit_time = NOW() WHERE log_id = ?", [req.body.logId]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`🚀 API running on port ${PORT}`);
    });
}

module.exports = app; 