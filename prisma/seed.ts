import { PrismaClient, Role } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
    console.log('🌱 Starting seed...');

    // Create Admin user
    const adminPassword = await bcrypt.hash('Admin@123', 12);
    const admin = await prisma.user.upsert({
        where: { email: 'admin@proctiq.com' },
        update: {},
        create: {
            email: 'admin@proctiq.com',
            password: adminPassword,
            name: 'System Admin',
            role: Role.ADMIN,
        },
    });
    console.log(`✅ Admin user created: ${admin.email}`);

    // Create Company user
    const companyPassword = await bcrypt.hash('Company@123', 12);
    const companyUser = await prisma.user.upsert({
        where: { email: 'company@acme.com' },
        update: {},
        create: {
            email: 'company@acme.com',
            password: companyPassword,
            name: 'Acme Recruiter',
            role: Role.COMPANY,
        },
    });

    const company = await prisma.company.upsert({
        where: { userId: companyUser.id },
        update: {},
        create: {
            name: 'Acme Corporation',
            description: 'Leading tech company',
            website: 'https://acme.com',
            userId: companyUser.id,
        },
    });
    console.log(`✅ Company created: ${company.name}`);

    // Create Candidate user
    const candidatePassword = await bcrypt.hash('Candidate@123', 12);
    const candidate = await prisma.user.upsert({
        where: { email: 'candidate@email.com' },
        update: {},
        create: {
            email: 'candidate@email.com',
            password: candidatePassword,
            name: 'John Doe',
            role: Role.CANDIDATE,
        },
    });
    console.log(`✅ Candidate created: ${candidate.email}`);

    // Create Sample Exam
    const exam = await prisma.exam.create({
        data: {
            title: 'JavaScript Fundamentals',
            description: 'Test your knowledge of JavaScript basics',
            duration: 30,
            totalMarks: 20,
            isPublished: true,
            companyId: company.id,
            questions: {
                create: [
                    {
                        questionText: 'What is the typeof null in JavaScript?',
                        options: ['null', 'undefined', 'object', 'number'],
                        correctAnswer: 'object',
                        marks: 5,
                    },
                    {
                        questionText: 'Which method converts JSON string to object?',
                        options: [
                            'JSON.stringify()',
                            'JSON.parse()',
                            'JSON.convert()',
                            'JSON.toObject()',
                        ],
                        correctAnswer: 'JSON.parse()',
                        marks: 5,
                    },
                    {
                        questionText: 'What is the output of typeof NaN?',
                        options: ['NaN', 'undefined', 'number', 'object'],
                        correctAnswer: 'number',
                        marks: 5,
                    },
                    {
                        questionText: 'Which keyword is used to declare a block-scoped variable?',
                        options: ['var', 'let', 'both var and let', 'none'],
                        correctAnswer: 'let',
                        marks: 5,
                    },
                ],
            },
        },
    });
    console.log(`✅ Sample exam created: ${exam.title} (${exam.id})`);

    // Create Audit Log for seed
    await prisma.auditLog.create({
        data: {
            userId: admin.id,
            action: 'SEED',
            entity: 'System',
            metadata: { message: 'Database seeded successfully' },
        },
    });

    console.log('🎉 Seed completed successfully!');
    console.log('\n📋 Test Credentials:');
    console.log('  Admin:     admin@proctiq.com / Admin@123');
    console.log('  Company:   company@acme.com / Company@123');
    console.log('  Candidate: candidate@email.com / Candidate@123');
}

main()
    .catch((e) => {
        console.error('❌ Seed failed:', e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
