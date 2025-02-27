import cors from 'cors';
import allowedOrigins from './allowedOrigins';

const corsOption: cors.CorsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed'), false);
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
};

export default corsOption;
