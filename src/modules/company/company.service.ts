import {
    Injectable,
    NotFoundException,
    ConflictException,
    ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateCompanyDto, UpdateCompanyDto } from './dto';

@Injectable()
export class CompanyService {
    constructor(private prisma: PrismaService) { }

    async createCompany(userId: string, dto: CreateCompanyDto) {
        const existingCompany = await this.prisma.company.findUnique({
            where: { userId },
        });

        if (existingCompany) {
            throw new ConflictException('Company profile already exists for this user');
        }

        return this.prisma.company.create({
            data: {
                ...dto,
                userId,
            },
        });
    }

    async updateCompany(companyId: string, userId: string, dto: UpdateCompanyDto) {
        const company = await this.prisma.company.findUnique({
            where: { id: companyId },
        });

        if (!company) {
            throw new NotFoundException('Company not found');
        }

        if (company.userId !== userId) {
            throw new ForbiddenException('Not authorized to update this company');
        }

        return this.prisma.company.update({
            where: { id: companyId },
            data: { ...dto },
        });
    }

    async getCompanyById(companyId: string) {
        const company = await this.prisma.company.findUnique({
            where: { id: companyId },
            include: {
                user: {
                    select: { id: true, email: true, name: true },
                },
            },
        });

        if (!company) {
            throw new NotFoundException('Company not found');
        }

        return company;
    }

    async getDashboard(userId: string) {
        const company = await this.prisma.company.findUnique({
            where: { userId },
        });

        if (!company) {
            throw new NotFoundException('Company profile not found');
        }

        const [totalExams, publishedExams, totalAttempts, averageScore] =
            await Promise.all([
                this.prisma.exam.count({
                    where: { companyId: company.id, isDeleted: false },
                }),
                this.prisma.exam.count({
                    where: { companyId: company.id, isPublished: true, isDeleted: false },
                }),
                this.prisma.attempt.count({
                    where: { exam: { companyId: company.id } },
                }),
                this.prisma.attempt.aggregate({
                    where: {
                        exam: { companyId: company.id },
                        status: { not: 'IN_PROGRESS' },
                    },
                    _avg: { score: true },
                }),
            ]);

        return {
            company,
            stats: {
                totalExams,
                publishedExams,
                totalAttempts,
                averageScore: averageScore._avg.score
                    ? Math.round(averageScore._avg.score * 100) / 100
                    : 0,
            },
        };
    }
}
