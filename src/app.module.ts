import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD, APP_FILTER, APP_INTERCEPTOR } from '@nestjs/core';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';

import configuration from './config/configuration';
import { PrismaModule } from './prisma/prisma.module';
import { RedisModule } from './redis/redis.module';

import { JwtAuthGuard } from './common/guards/jwt-auth.guard';
import { CustomThrottleGuard } from './common/guards/custom-throttle.guard';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { TransformInterceptor } from './common/interceptors/transform.interceptor';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';

import { AuthModule } from './modules/auth/auth.module';
import { UserModule } from './modules/user/user.module';
import { CompanyModule } from './modules/company/company.module';
import { ExamModule } from './modules/exam/exam.module';
import { AttemptModule } from './modules/attempt/attempt.module';
import { ProctoringModule } from './modules/proctoring/proctoring.module';
import { AuditModule } from './modules/audit/audit.module';
import { OtpModule } from './modules/otp/otp.module';
import { DeviceModule } from './modules/device/device.module';

@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
    }),

    // Global Rate Limiting (fallback for undecorated routes)
    ThrottlerModule.forRootAsync({
      useFactory: (configService: ConfigService) => ([{
        ttl: configService.get<number>('throttle.ttl') ?? 60000,
        limit: configService.get<number>('throttle.limit') ?? 100,
      }]),
      inject: [ConfigService],
    }),

    // Infrastructure
    PrismaModule,
    RedisModule,

    // Security Modules
    OtpModule,
    AuditModule,

    // Feature Modules
    AuthModule,
    UserModule,
    CompanyModule,
    ExamModule,
    AttemptModule,
    ProctoringModule,
    DeviceModule,
  ],
  providers: [
    // Global JWT Guard (applied to all routes, bypass with @Public())
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    // Global Rate Limiting Guard (fallback)
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    // Per-endpoint Redis Rate Limiting Guard
    {
      provide: APP_GUARD,
      useClass: CustomThrottleGuard,
    },
    // Global Exception Filter
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
    // Global Response Transform Interceptor
    {
      provide: APP_INTERCEPTOR,
      useClass: TransformInterceptor,
    },
    // Global Logging Interceptor
    {
      provide: APP_INTERCEPTOR,
      useClass: LoggingInterceptor,
    },
  ],
})
export class AppModule { }
