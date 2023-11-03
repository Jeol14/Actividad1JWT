import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";

const app = express();
const port = 5000;

app.use(express.json());
app.use(cookieParser());

app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    // Verifica que los campos name, email y password no estén vacíos
    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Por favor, proporcione nombre, correo electrónico y contraseña.' });
    }


    // Genera una sal para usar en el hash de la contraseña
    const salt = await bcrypt.genSalt(10);

    // Hashea la contraseña usando la sal generada
    const hashedPassword = await bcrypt.hash(password, salt);

    const connection = await mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: '1234',
        database: 'loginjwt'
    });

    try {
        const [results] = await connection.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword]);
        res.json({ message: 'Registro de usuario exitoso' });
    } catch (error) {
        console.error('Error al registrar el usuario:', error);
        res.sendStatus(500);
    } finally {
        await connection.end();
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    const connection = await mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: '1234',
        database: 'loginjwt'
    });

    try {
        const [results] = await connection.execute('SELECT id, name, email, password FROM users WHERE email = ?', [email]);
        if (results.length === 0) {
            res.sendStatus(401);
        } else {
            const user = results[0];
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {
                const token = jwt.sign({ user }, 'secretkey', { expiresIn: '120s' });
                res.cookie('jwtToken', token, { httpOnly: true });
                res.json({ message: 'Inicio de sesión exitoso' });
            } else {
                res.sendStatus(401);
            }
        }
    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.sendStatus(500);
    } finally {
        await connection.end();
    }
});

app.post('/api/protected', verifytoken, (req, res) => {
    jwt.verify(req.token, 'secretkey', (error, authData) => {
        if (error) {
            res.sendStatus(403);
        } else {
            res.json({
                message: "Ruta protegida"
            });
        }
    });
});

function verifytoken(req, res, next) {
    const token = req.cookies.jwtToken;

    if (token) {
        req.token = token;
        next();
    } else {
        res.sendStatus(403);
    }
}

app.listen(port, () => {
    console.log(`Servidor en funcionamiento en el puerto ${port}`);
});
