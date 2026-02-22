import {
    Injectable,
    CanActivate,
    ExecutionContext,
    HttpException,
    HttpStatus,
    Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RedisService } from '../../redis/redis.service';

export const RATE_LIMIT_KEY = 'rate-limit';

export interface RateLimitConfig {
    /** Max requests allowed in the window */
    limit: number;
    /** Time window in seconds */
    windowSec: number;
    /** Custom key prefix (defaults to route path) */
    keyPrefix?: string;
}

/**
 * Decorator to set per-endpoint rate limit config
 */
export const RateLimit = (config: RateLimitConfig) =>
    (target: any, key?: string, descriptor?: PropertyDescriptor) => {
        if (descriptor) {
            Reflect.defineMetadata(RATE_LIMIT_KEY, config, descriptor.value);
        }
        return descriptor;
    };

/**
 * Redis-based per-endpoint rate limiter guard.
 * Apply @RateLimit({ limit: 5, windowSec: 60 }) on individual endpoints.
 * Falls through silently if no @RateLimit decorator is present.
 */
@Injectable()
export class CustomThrottleGuard implements CanActivate {
    private readonly logger = new Logger(CustomThrottleGuard.name);

    constructor(
        private redisService: RedisService,
        private reflector: Reflector,
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const handler = context.getHandler();
        const config = Reflect.getMetadata(RATE_LIMIT_KEY, handler) as RateLimitConfig | undefined;

        // No rate limit decorator — allow through
        if (!config) {
            return true;
        }

        const request = context.switchToHttp().getRequest();
        const ip = (request.headers['x-forwarded-for'] as string) || request.ip || 'unknown';
        const keyPrefix = config.keyPrefix || request.route?.path || request.url;
        const key = `rate:${keyPrefix}:${ip}`;

        const current = await this.redisService.incr(key);

        // Set TTL on first request in window
        if (current === 1) {
            await this.redisService.expire(key, config.windowSec);
        }

        if (current > config.limit) {
            const ttl = await this.redisService.ttl(key);

            this.logger.warn(
                `Rate limit exceeded: ${ip} on ${keyPrefix} (${current}/${config.limit})`,
            );

            throw new HttpException(
                {
                    success: false,
                    message: `Too many requests. Try again in ${ttl} seconds.`,
                    data: null,
                },
                HttpStatus.TOO_MANY_REQUESTS,
            );
        }

        return true;
    }
}
