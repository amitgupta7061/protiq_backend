import { Injectable, OnModuleDestroy, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleDestroy {
    private readonly client: Redis;
    private readonly logger = new Logger(RedisService.name);

    constructor(private configService: ConfigService) {
        this.client = new Redis({
            host: this.configService.get<string>('redis.host', 'localhost'),
            port: this.configService.get<number>('redis.port', 6379),
            password: this.configService.get<string>('redis.password') || undefined,
            retryStrategy: (times: number) => {
                if (times > 3) {
                    this.logger.warn('Redis connection failed after 3 retries');
                    return null;
                }
                return Math.min(times * 200, 2000);
            },
        });

        this.client.on('error', (err) => {
            this.logger.error(`Redis connection error: ${err.message}`);
        });

        this.client.on('connect', () => {
            this.logger.log('Redis connected successfully');
        });
    }

    getClient(): Redis {
        return this.client;
    }

    async get(key: string): Promise<string | null> {
        return this.client.get(key);
    }

    async set(key: string, value: string, ttl?: number): Promise<void> {
        if (ttl) {
            await this.client.set(key, value, 'EX', ttl);
        } else {
            await this.client.set(key, value);
        }
    }

    async del(key: string): Promise<void> {
        await this.client.del(key);
    }

    async incr(key: string): Promise<number> {
        return this.client.incr(key);
    }

    async expire(key: string, ttl: number): Promise<void> {
        await this.client.expire(key, ttl);
    }

    async exists(key: string): Promise<boolean> {
        const result = await this.client.exists(key);
        return result === 1;
    }

    async ttl(key: string): Promise<number> {
        return this.client.ttl(key);
    }

    async setJson(key: string, value: Record<string, any>, ttl?: number): Promise<void> {
        await this.set(key, JSON.stringify(value), ttl);
    }

    async getJson<T = Record<string, any>>(key: string): Promise<T | null> {
        const data = await this.get(key);
        if (!data) return null;
        try {
            return JSON.parse(data) as T;
        } catch {
            return null;
        }
    }

    async onModuleDestroy() {
        await this.client.quit();
    }
}
