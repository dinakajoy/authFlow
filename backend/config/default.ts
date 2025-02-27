import dotenv from 'dotenv-safe';

dotenv.config();

export default {
  environment: {
    host: process.env.HOST || '0.0.0.0',
    port: Number(String(process.env.PORT)) || 5000,
    saltWorkFactor: Number(String(process.env.SALT_GEN)) || 10,
  },
  dbConfig: {
    url: process.env.DATABASE_URL || '',
  },
};
