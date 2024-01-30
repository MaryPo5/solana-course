---
назва: зіставлення даних облікового запису
цілі:
- Пояснення ризиків безпеки, пов'язаних з відсутніми даними валідаційних перевірок
- Реалізація перевірки даних за допомогою Rust у довгій формі
- Реалізація валідаційної перевірки даних за допомогою обмежень Anchor
---

# Тези

- Використовуйте **data validation checks** (валідаційну перевірку даних), щоб переконатися, що дані облікового запису відповідають очікуваному значенню. Без відповідних перевірок підтвердження даних в інструкції можуть використовуватися неочікувані облікові записи.
- Щоб застосувати перевірку даних у Rust, просто порівняйте дані, що зберігаються в обліковому записі, з очікуваним значенням.
    
    ```rust
    if ctx.accounts.user.key() != ctx.accounts.user_data.user {
        return Err(ProgramError::InvalidAccountData.into());
    }
    ```
    
- У Anchor ви можете використовувати `constraint`, щоб перевірити, чи даний вираз має true/правдиве значення. Крім того, ви можете використовувати `has_one`, щоб перевірити, чи поле цільового облікового запису, збережене в обліковому записі, відповідає ключу облікового запису в структурі `Accounts`.

# Огляд

Зіставлення даних облікового запису відноситься до перевірки даних, які використовуються для перевірки того, що дані, збережені в обліковому записі, відповідають очікуваному значенню. Перевірки перевірки даних надають можливість включити додаткові обмеження, щоб забезпечити передачу відповідних облікових записів в інструкції.

Це може бути корисно, коли облікові записи, які вимагаються інструкцією, залежать від значень, що зберігаються в інших облікових записах, або якщо інструкція залежить від даних, що зберігаються в обліковому записі.

### Втрата інформації перевірки валідації

Наведений нижче приклад містить інструкцію `update_admin`, яка оновлює поле `admin`, збережене в обліковому записі `admin_config`.

У інструкції відсутня перевірка валідація даних, щоб верифікувати, що обліковий запис `admin`, який підписує транзакцію, збігається з `admin`, збереженим в обліковому записі `admin_config`. Це означає, що будь-який обліковий запис, який підписує транзакцію та передається в інструкцію як обліковий запис `admin`, може оновлювати обліковий запис `admin_config`.

```rust
use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod data_validation {
    use super::*;
    ...
    pub fn update_admin(ctx: Context<UpdateAdmin>) -> Result<()> {
        ctx.accounts.admin_config.admin = ctx.accounts.new_admin.key();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateAdmin<'info> {
    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub new_admin: SystemAccount<'info>,
}

#[account]
pub struct AdminConfig {
    admin: Pubkey,
}
```

### Додати перевірку валідації даних

Основний підхід Rust до вирішення цієї проблеми полягає в тому, щоб просто порівняти переданий ключ `admin` з ключем `admin`, який зберігається в обліковому записі `admin_config`, видаючи помилку, якщо вони не збігаються.

```rust
if ctx.accounts.admin.key() != ctx.accounts.admin_config.admin {
    return Err(ProgramError::InvalidAccountData.into());
}
```

Додавши перевірку перевірки даних, інструкція `update_admin` оброблятиметься, лише якщо підписувач транзакції `admin` збігатиметься з `admin`, збереженим в обліковому записі `admin_config`.

```rust
use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod data_validation {
    use super::*;
    ...
    pub fn update_admin(ctx: Context<UpdateAdmin>) -> Result<()> {
      if ctx.accounts.admin.key() != ctx.accounts.admin_config.admin {
            return Err(ProgramError::InvalidAccountData.into());
        }
        ctx.accounts.admin_config.admin = ctx.accounts.new_admin.key();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateAdmin<'info> {
    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub new_admin: SystemAccount<'info>,
}

#[account]
pub struct AdminConfig {
    admin: Pubkey,
}
```

### Використовуйте обмеження Anchor

Anchor спрощує це за допомогою обмеження has_one. Ви можете використовувати обмеження `has_one`, щоб перемістити перевірку перевірки даних із логіки інструкцій у структуру `UpdateAdmin`.

У наведеному нижче прикладі `has_one = admin` вказує, що обліковий запис `admin`, який підписує транзакцію, має відповідати полю `admin`, збереженому в обліковому записі `admin_config`. Щоб використовувати обмеження has_one, угода про іменування поля даних в обліковому записі має відповідати іменуванню в структурі перевірки облікового запису.

```rust
use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod data_validation {
    use super::*;
    ...
    pub fn update_admin(ctx: Context<UpdateAdmin>) -> Result<()> {
        ctx.accounts.admin_config.admin = ctx.accounts.new_admin.key();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UpdateAdmin<'info> {
    #[account(
        mut,
        has_one = admin
    )]
    pub admin_config: Account<'info, AdminConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub new_admin: SystemAccount<'info>,
}

#[account]
pub struct AdminConfig {
    admin: Pubkey,
}
```

Крім того, ви можете використати `constraint`, щоб вручну додати вираз, який має мати значення true, щоб виконання продовжилося. Це корисно, коли з якихось причин іменування не може бути послідовним або коли вам потрібен більш складний вираз для повної перевірки вхідних даних.

```rust
#[derive(Accounts)]
pub struct UpdateAdmin<'info> {
    #[account(
        mut,
        constraint = admin_config.admin == admin.key()
    )]
    pub admin_config: Account<'info, AdminConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub new_admin: SystemAccount<'info>,
}
```

# Лабораторія

Для цієї лабораторної роботи ми створимо просту програму «сховище», схожу на програму, яку ми використовували в уроці «Авторизація підписувача» та «Перевірка власника». Подібно до цих лабораторних робіт, у цій лабораторній роботі ми покажемо, як відсутність перевірки валідації даних може дозволити спорожнити сховище.

### 1.Стартер

Щоб розпочати, завантажте стартовий код із гілки `starter` [цього репозиторію](https://github.com/Unboxed-Software/solana-account-data-matching). Початковий код містить програму з двома інструкціями та шаблонні налаштування для тестового файлу.

Інструкція `initialize_vault` ініціалізує новий обліковий запис `Vault` і новий `TokenAccount`. Обліковий запис `Vault` зберігатиме адресу маркерного облікового запису, повноваження сховища та обліковий запис маркера призначення вилучення.

Повноваження нового маркерного облікового запису буде встановлено як `vault`, PDA програми. Це дозволяє обліковому запису `vault` підписати для передачі токенів з облікового запису токенів.

Інструкція `insecure_withdraw` переносить усі токени в обліковому записі маркерів `vault` до облікового запису маркерів`withdraw_destination`.

Зауважте, що ця інструкція ****дійсно**** має перевірку підпису для `authority` та перевірку власника для `vault`. Однак ніде в логіці перевірки облікового запису чи інструкції немає коду, який перевіряє, чи обліковий запис `authority`, переданий у інструкцію, збігається з обліковим записом `authority` у `vault`.

```rust
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod account_data_matching {
    use super::*;

    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        ctx.accounts.vault.token_account = ctx.accounts.token_account.key();
        ctx.accounts.vault.authority = ctx.accounts.authority.key();
        ctx.accounts.vault.withdraw_destination = ctx.accounts.withdraw_destination.key();
        Ok(())
    }

    pub fn insecure_withdraw(ctx: Context<InsecureWithdraw>) -> Result<()> {
        let amount = ctx.accounts.token_account.amount;

        let seeds = &[b"vault".as_ref(), &[*ctx.bumps.get("vault").unwrap()]];
        let signer = [&seeds[..]];

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.token_account.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.withdraw_destination.to_account_info(),
            },
            &signer,
        );

        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 32 + 32,
        seeds = [b"vault"],
        bump,
    )]
    pub vault: Account<'info, Vault>,
    #[account(
        init,
        payer = authority,
        token::mint = mint,
        token::authority = vault,
        seeds = [b"token"],
        bump,
    )]
    pub token_account: Account<'info, TokenAccount>,
    pub withdraw_destination: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct InsecureWithdraw<'info> {
    #[account(
        seeds = [b"vault"],
        bump,
    )]
    pub vault: Account<'info, Vault>,
    #[account(
        mut,
        seeds = [b"token"],
        bump,
    )]
    pub token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub withdraw_destination: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    token_account: Pubkey,
    authority: Pubkey,
    withdraw_destination: Pubkey,
}
```

### 2. Протестуйте інструкцію `insecure_withdraw`

Щоб довести, що це проблема, давайте напишемо тест, у якому обліковий запис, відмінний від `authority` сховища, намагається вийти зі сховища.

Тестовий файл містить код для виклику інструкції `initialize_vault`, використовуючи гаманець постачальника як `authority`, а потім карбує 100 токенів до облікового запису токенів `vault`.

Додайте тест для виклику інструкції `insecure_withdraw`. Використовуйте `withdrawDestinationFake` як обліковий запис `withdrawDestination` і `walletFake` як ``authority`. Потім надішліть транзакцію за допомогою `walletFake`.

Оскільки немає жодних перевірок, які підтверджують, що обліковий запис `authority`, переданий в інструкцію, відповідає значенням, збереженим в обліковому записі `vault`, ініціалізованому під час першого тесту, інструкцію буде оброблено успішно, а токени буде передано в обліковий запис `withdrawDestinationFake`.

```tsx
describe("account-data-matching", () => {
  ...
  it("Insecure withdraw", async () => {
    const tx = await program.methods
      .insecureWithdraw()
      .accounts({
        vault: vaultPDA,
        tokenAccount: tokenPDA,
        withdrawDestination: withdrawDestinationFake,
        authority: walletFake.publicKey,
      })
      .transaction()

    await anchor.web3.sendAndConfirmTransaction(connection, tx, [walletFake])

    const balance = await connection.getTokenAccountBalance(tokenPDA)
    expect(balance.value.uiAmount).to.eq(0)
  })
})
```

Запустіть `anchor test`, щоб переконатися, що обидві транзакції завершаться успішно.

```bash
account-data-matching
  ✔ Initialize Vault (811ms)
  ✔ Insecure withdraw (403ms)
```

### 3. Додайте інструкцію `secure_withdraw`

Давайте впровадимо безпечну версію цієї інструкції під назвою `secure_withdraw`.

Ця інструкція буде ідентичною інструкції `insecure_withdraw`, за винятком того, що ми використаємо обмеження `has_one` у структурі перевірки облікового запису (`SecureWithdraw`), щоб перевірити, чи обліковий запис `authority`, переданий в інструкцію, відповідає обліковому запису `authority` на рахунок `vault`. Таким чином, лише правильний авторизований обліковий запис може вилучати токени зі сховища.

```rust
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod account_data_matching {
    use super::*;
    ...
    pub fn secure_withdraw(ctx: Context<SecureWithdraw>) -> Result<()> {
        let amount = ctx.accounts.token_account.amount;

        let seeds = &[b"vault".as_ref(), &[*ctx.bumps.get("vault").unwrap()]];
        let signer = [&seeds[..]];

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.token_account.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.withdraw_destination.to_account_info(),
            },
            &signer,
        );

        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SecureWithdraw<'info> {
    #[account(
        seeds = [b"vault"],
        bump,
        has_one = token_account,
        has_one = authority,
        has_one = withdraw_destination,

    )]
    pub vault: Account<'info, Vault>,
    #[account(
        mut,
        seeds = [b"token"],
        bump,
    )]
    pub token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub withdraw_destination: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub authority: Signer<'info>,
}
```

### 4. Перевірте інструкцію `secure_withdraw`

Тепер давайте перевіримо інструкцію `secure_withdraw` за допомогою двох тестів: один використовує `walletFake` як повноваження, а другий використовує `wallet` як повноваження. Ми очікуємо, що перший виклик поверне помилку, а другий буде успішним.

```tsx
describe("account-data-matching", () => {
  ...
  it("Secure withdraw, expect error", async () => {
    try {
      const tx = await program.methods
        .secureWithdraw()
        .accounts({
          vault: vaultPDA,
          tokenAccount: tokenPDA,
          withdrawDestination: withdrawDestinationFake,
          authority: walletFake.publicKey,
        })
        .transaction()

      await anchor.web3.sendAndConfirmTransaction(connection, tx, [walletFake])
    } catch (err) {
      expect(err)
      console.log(err)
    }
  })

  it("Secure withdraw", async () => {
    await spl.mintTo(
      connection,
      wallet.payer,
      mint,
      tokenPDA,
      wallet.payer,
      100
    )

    await program.methods
      .secureWithdraw()
      .accounts({
        vault: vaultPDA,
        tokenAccount: tokenPDA,
        withdrawDestination: withdrawDestination,
        authority: wallet.publicKey,
      })
      .rpc()

    const balance = await connection.getTokenAccountBalance(tokenPDA)
    expect(balance.value.uiAmount).to.eq(0)
  })
})
```

Запустіть `anchor test`, щоб побачити, що транзакція з використанням неправильного облікового запису повноважень тепер повертатиме помилку прив’язки, тоді як транзакція з використанням правильних облікових записів завершиться успішно.

```bash
'Program Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS invoke [1]',
'Program log: Instruction: SecureWithdraw',
'Program log: AnchorError caused by account: vault. Error Code: ConstraintHasOne. Error Number: 2001. Error Message: A has one constraint was violated.',
'Program log: Left:',
'Program log: DfLZV18rD7wCQwjYvhTFwuvLh49WSbXFeJFPQb5czifH',
'Program log: Right:',
'Program log: 5ovvmG5ntwUC7uhNWfirjBHbZD96fwuXDMGXiyMwPg87',
'Program Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS consumed 10401 of 200000 compute units',
'Program Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS failed: custom program error: 0x7d1'
```

Зверніть увагу, що Anchor вказує в журналах обліковий запис, який викликає помилку (`AnchorError caused by account: vault`).

```bash
✔ Secure withdraw, expect error (77ms)
✔ Secure withdraw (10073ms)
```

І таким чином ви закрили лазівку в безпеці. Тема більшості цих потенційних експлойтів полягає в тому, що вони досить прості. Однак по мірі збільшення масштабів і складності ваших програм стає дедалі легше пропустити можливі експлойти. Чудово мати звичку писати тести, які надсилають інструкції, які *не повинні* працювати. Чим більше, тим краще. Таким чином ви виявите проблеми перед розгортанням.

Якщо ви хочете переглянути остаточний код рішення, ви можете знайти його у гілці `solution` [репозиторію](https://github.com/Unboxed-Software/solana-account-data-matching/tree/solution).

# Виклик

Як і в інших уроках цього розділу, ваша можливість потренуватися уникати цього експлойту безпеки полягає в перевірці власних або інших програм.

Виділіть деякий час, щоб переглянути принаймні одну програму та переконатися, що належні перевірки даних є на місці, щоб уникнути експлойтів безпеки.

Пам’ятайте: якщо ви знайшли помилку чи експлойт у чиїйсь програмі, повідомте про це! Якщо ви знайшли такий у своїй програмі, обов’язково негайно виправте його.

## Закінчили лабораторію?

Надішліть свій код на GitHub і [розкажіть нам, що ви думаєте про цей урок](https://form.typeform.com/to/IPH0UGz7#answers-lesson=a107787e-ad33-42bb-96b3-0592efc1b92f)!
