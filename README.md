# Health Connected Backend

## Fluxo obrigatorio de acesso
1. Cadastro
2. Verificacao de email por codigo (6 digitos)
3. Aceite de Termos e Privacidade
4. Onboarding clinico (tipo sanguineo, documento, contacto de emergencia e dados de saude)
5. Acesso a plataforma

## Regras extras
- Profissional so tem acesso completo apos aprovacao da carteira pelo gestor.
- Consentimento de dados sensiveis e por consulta.
  - Sem consentimento: profissional ve apenas alias (Paciente 1, Paciente 2...).
  - Com consentimento: profissional ve dados daquela consulta pendente.
  - Consulta fechada: acesso sensivel e revogado.
- Gestor pode acompanhar tudo para governanca, com responsabilidade de privacidade.

## Funcionalidades implementadas
- Alertas de surtos para gestores (dashboard + envio por email)
- Receitas em PDF
- Registros medicos em PDF
- Envio de receita PDF para paciente por email
- Dashboard de Dados Gerais exclusivo de gestores

## Configuracao
Copie `.env.example` para `.env`:
- `PORT`
- `MONGO_URI`
- `JWT_SECRET`
- `CORS_ORIGIN`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `EMAIL_FROM`

## Execucao
```bash
npm install
npm start
```

## Paginas chave
- `login.html`
- `VERIFY_EMAIL.html`
- `TERMS.html`
- `ONBOARDING.html`
- `HOME 2.html`
- `DADOS_GERAIS.html` (gestor)
- `GESTOR_PANEL.html`
- `PROFISSIONAL_PANEL.html`

## Endpoints relevantes
- Email/termos/onboarding:
  - `POST /auth/verify-email/send`
  - `POST /auth/verify-email/confirm`
  - `GET /auth/terms`
  - `POST /auth/terms/accept`
  - `POST /auth/terms/reject`
  - `POST /auth/onboarding`
- Profissionais:
  - `GET /api/consultas/pendentes/profissional`
  - `POST /api/consultas/:id/atender`
  - `POST /api/consultas/:id/receita`
  - `POST /api/consultas/:id/receita/enviar`
- Pacientes:
  - `POST /api/consultas`
  - `GET /api/consultas/minhas`
  - `POST /api/consultas/:id/consent`
  - `GET /api/consultas/:id/registro.pdf`
  - `GET /api/consultas/:id/receita.pdf`
- Gestores:
  - `GET /api/surtos`
  - `GET /api/gestor/alerts`
  - `GET /api/gestor/profissionais-pendentes`
  - `POST /api/gestor/profissionais/:id/aprovar`
  - `POST /api/gestor/profissionais/:id/rejeitar`
