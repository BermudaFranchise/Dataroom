# FundRoom.ai — Multi-Tenant SaaS Platform

## Overview
FundRoom.ai is a multi-tenant SaaS platform that helps GPs and startups manage fundraising, investor onboarding, document sharing, compliance, and capital movement. Organizations (customers) sign up, configure their workspace, and invite their investors — all under FundRoom's infrastructure with optional custom branding and domains.

**FundRoom.ai is the platform company. Individual organizations (e.g., Bermuda Franchise Group) are customers using the platform.**

## Domain Architecture
| Domain | Purpose |
|--------|---------|
| `fundroom.ai` | Marketing site — company info, pricing, signup CTA |
| `app.fundroom.ai` | Organization signup & setup wizard — new customers join here |
| `app.login.fundroom.ai` | FundRoom-branded admin login portal — existing customers access their backend dashboards |
| `[custom].example.com` | Optional per-org branded portals (e.g., `fundroom.bermudafranchisegroup.com`) — admins and investors access org-specific portal |

## User Preferences
- Communication: Simple, everyday language
- Technical level: Non-technical explanations preferred
- Focus: Security and ease of use for investors
- **GitHub Integration**: FUNDROOM_GITHUB_PAT secret is available — always use GitHub API to push changes directly. The repo is `FundRoomAI/app`. Use the GitHub Contents API or Git Trees API to push files.
- **Vercel Pro**: Team `team_1LMzKEn5ldhAciRMQQltwHxk`, Project `prj_kbtv1UmLSFVn9LzYRsEddhbPPVmA` (app). VERCEL_TOKEN secret available for API operations. Domains: `fundroom.ai`, `app.fundroom.ai`, `app.login.fundroom.ai`.
- **Tinybird**: Workspace `fundroomia_workspace`, Region US West 2 (`api.us-west-2.aws.tinybird.co`).

## System Architecture
The platform is built with Next.js 16.x (App Router), React, TypeScript, Tailwind CSS, shadcn/ui, PostgreSQL (via Prisma ORM), and NextAuth.js v4.

### Multi-Tenant Model
- **Organization** = a customer company (GP firm, startup, etc.)
- **Team** = a workspace within an org (may have multiple funds/raises)
- **Fund/Raise** = a specific fundraise within a team
- **User** = platform user; may belong to multiple orgs with different roles
- Every database row is scoped to `org_id`; all queries enforce tenant isolation

### Two Operating Modes
- **GP FUND** mode: LPA-based funds, capital calls, K-1s, distributions, LP portal
- **STARTUP** mode: SAFE/priced rounds, cap table, vesting schedules

### Domain Routing
The platform uses host-based routing in middleware:
- Requests to `app.fundroom.ai` → org signup/onboarding wizard
- Requests to `app.login.fundroom.ai` → FundRoom-branded login → admin dashboard
- Requests to custom domains → org lookup by domain → branded portal with org branding
- `fundroom.ai` → marketing site (may be separate or same Next.js app)

**Core Features**:
- **Compliance**: 506(c) accreditation, KYC/AML, and audit logging
- **E-Signature**: Self-hosted, ESIGN/UETA compliant signature workflows
- **Portals**: Personalized LP (Investor) portal with RBAC and watermarked documents, and comprehensive Admin Dashboards
- **Payment Flows**: ACH for capital calls and Stripe for platform billing
- **PWA Support**: For offline access
- **Push Notifications**: Real-time alerts
- **Reporting**: Advanced custom report builder with export capabilities
- **Audit Logging**: Comprehensive, centralized, immutable audit logging with 7-year retention and tamper detection using SHA-256 hash chaining
- **Soft-Delete**: For key database models (`Document`, `Dataroom`, `Team`)

**Security Features**:
- **Encryption**: Three-layer encryption (TLS 1.3, Server-Side AES-256-GCM, PDF 2.0 AES-256) and client-side WebCrypto AES-256-GCM for documents
- **Path Traversal Protection**: For all file operations
- **URL Validation**: For external links with domain allowlists
- **Admin Email Security**: Using magic links for secure routing

**Authentication System**:
- **Providers**: NextAuth.js supports magic links (email), Google OAuth, and LinkedIn OAuth
- **Session Strategy**: JWT-based sessions (30-day max age) for Edge middleware compatibility
- **Role Detection**: Users with OWNER/ADMIN/SUPER_ADMIN team roles automatically get GP role
- **Access Control**: Strict portal-based access control with distinct admin and investor portals

**Enterprise Provisioning**:
- Supports multi-tenant enterprise setups with `Organization` and `OrganizationDefaults` models
- Features include Organization Setup Wizard, SSO (SAML, OIDC, Azure AD, Okta, Google Workspace), promotable defaults, lockable policies, and encrypted integration credentials

**AI Integration**:
- Uses OpenAI as the primary AI provider with Replit AI Integration as a fallback

**Modular Feature Architecture**:
- All major capabilities are feature-modules that can be enabled/disabled per Organization and/or Fund (e.g., Auth + Accounts, Dataroom, E-Signature, KYC/AML, Payments)

**Feature Flag System**:
- Hierarchical system with resolution order: System Defaults → Organization → Team → Fund

**Provider Interfaces**:
- All vendors are abstracted behind provider interfaces using a plugin architecture

## External Dependencies
- **Resend**: Transactional email service
- **Persona**: KYC/AML verification
- **Plaid**: Bank connectivity for ACH payments
- **Tinybird**: Real-time analytics
- **Stripe**: Platform billing
- **Rollbar**: Error monitoring
- **PostHog**: Product analytics
- **Google OAuth**: For admin authentication
- **OpenAI**: Primary AI features
- **Replit AI Integration**: Fallback AI provider
- **Replit Object Storage**: Default document storage
- **Web Push**: For push notifications

## Key Deployment Info
- **Hosting**: Vercel Pro
- **Database**: PostgreSQL (Neon-backed via Replit)
- **Primary Domain**: fundroom.ai
- **App Domains**: app.fundroom.ai, app.login.fundroom.ai
- **Custom Domains**: Per-org (e.g., fundroom.bermudafranchisegroup.com)
- **First Customer**: Bermuda Franchise Group (BFG)

