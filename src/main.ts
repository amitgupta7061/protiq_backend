import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'debug', 'verbose'],
  });

  const configService = app.get(ConfigService);
  const port = configService.get<number>('port', 3000);
  const apiPrefix = configService.get<string>('apiPrefix', 'api/v1');

  // Global Prefix
  app.setGlobalPrefix(apiPrefix);

  // ── Security Headers ──
  app.use(
    helmet({
      // Content Security Policy
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"], // swagger needs inline
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          frameSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
        },
      },
      // HTTP Strict Transport Security
      hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
      },
      // Prevent clickjacking
      frameguard: { action: 'deny' },
      // Disable X-Powered-By
      hidePoweredBy: true,
      // Prevent MIME type sniffing
      noSniff: true,
      // Referrer policy
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      // Cross-Origin resource policies
      crossOriginEmbedderPolicy: false, // allow API access
      crossOriginResourcePolicy: { policy: 'same-origin' },
    }),
  );

  app.use(cookieParser());

  // CORS
  app.enableCors({
    origin: configService.get<string>('cors.origin', 'http://localhost:3001'),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-Fingerprint'],
  });

  // Validation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Swagger Documentation
  const swaggerConfig = new DocumentBuilder()
    .setTitle('Proctiq API')
    .setDescription('Online Proctored Exam Platform API — Enterprise Security Edition')
    .setVersion('1.1')
    .addBearerAuth()
    .addTag('Authentication', 'Auth endpoints (OTP, 2FA, device trust)')
    .addTag('OTP', 'OTP verification endpoints')
    .addTag('Devices', 'Trusted device management')
    .addTag('Users', 'User management endpoints')
    .addTag('Companies', 'Company management endpoints')
    .addTag('Exams', 'Exam management endpoints')
    .addTag('Attempts', 'Exam attempt endpoints')
    .addTag('Proctoring', 'Proctoring log endpoints')
    .addTag('Audit Logs', 'Audit log endpoints')
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
  });

  await app.listen(port);
  logger.log(`🚀 Application running on: http://localhost:${port}`);
  logger.log(`📚 Swagger docs: http://localhost:${port}/api/docs`);
  logger.log(`🔗 API prefix: /${apiPrefix}`);
  logger.log(`🛡️  Security headers: CSP, HSTS, X-Frame-Options, noSniff enabled`);
}

bootstrap();
