import express, { Express, Request, Response, NextFunction } from 'express';
import compression from 'compression';
import createError from 'http-errors';
import cors from 'cors';
import permissionRoute from './permission/permission.route';
import userRoleRoute from './userRole/userRole.route';
import userRoute from './user/user.route';
import { rateLimiter, corsOption, allowedOrigins } from './utils';

const app: Express = express();

app.use(rateLimiter);

app.use((req: Request, res: Response, next: NextFunction) => {
  const { origin } = req.headers || '';
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Headers', 'true');
    res.header('Content-Type', 'application/json');
  }
  next();
});

app.use(cors<Request>(corsOption));
app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.get('/', async (req: Request, res: Response) => {
  res.status(200).json({ message: 'Awesome it works 🐻' });
});

app.use('/permissions', permissionRoute);
app.use('/user-role', userRoleRoute);
app.use('/user', userRoute);

// catch 404 and forward to error handler
app.use((req: Request, res: Response, next: NextFunction) => {
  next(new createError.NotFound());
});

// error handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  res.status(err.status || 500).json({
    status: 'error',
    errors: err.message,
  });
  return;
});

export default app;
