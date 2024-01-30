---
Заголовок: Довільний CPI
цілі:
- Поясніть ризики безпеки, пов'язані з викликом CPI для невідомої програми
- Продемонструйте, як модуль CPI Anchor запобігає цьому під час створення CPI від однієї прив'язаної програми до іншої
- Безпечно та надійно перетворюйте CPI з прив'язаної програми в довільну програму без прив’язки.
---

# Багато тексту

- Щоб створити CPI, цільова програма повинна бути передана в інструкцію виклику як обліковий запис. Це означає, що будь-яка цільова програма може бути передана в інструкцію. Ваша програма повинна перевіряти наявність неправильних або неочікуваних програм.
- Виконуйте перевірки програм у рідних програмах, просто порівнюючи відкритий ключ переданої програми з програмою, яку ви очікували.
- Якщо програма написана на Anchor, вона може мати загальнодоступний модуль CPI. Це робить виклик програми з іншої Anchor програми простим і безпечним. Модуль Anchor CPI автоматично перевіряє, чи адреса переданої програми відповідає адресі програми, що зберігається в модулі.

# Огляд

Міжпрограмний виклик (cross program invocation -CPI) — це коли одна програма викликає інструкцію іншої програми. «Довільний CPI» — це коли програма структурована так, щоб видавати CPI будь-якій програмі, переданій в інструкції, а не очікувати виконання CPI для однієї конкретної програми. Враховуючи, що користувачі інструкції вашої програми можуть передати будь-яку програму, яку вони бажають, у список облікових записів інструкції, неможливість перевірити адресу переданої програми призводить до того, що ваша програма виконує CPI для довільних програм.

Відсутність перевірки програми створює можливість для зловмисника передати програму, відмінну від очікуваної, змушуючи вихідну програму викликати інструкцію цієї таємничої програми. Невідомо, якими можуть бути наслідки цього CPI. Це залежить від логіки програми (як оригінальної програми, так і неочікуваної програми), а також від того, які інші облікові записи передаються в оригінальну інструкцію.

## Відсутність перевірки програми

Розглянемо для прикладу наступну програму. Інструкція `cpi` викликає інструкцію `transfer` у `token_program`, але немає коду, який перевіряє, чи обліковий запис `token_program`, переданий у інструкцію, насправді є програмою маркерів SPL.

```rust
use anchor_lang::prelude::*;
use anchor_lang::solana_program;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod arbitrary_cpi_insecure {
    use super::*;

    pub fn cpi(ctx: Context<Cpi>, amount: u64) -> ProgramResult {
        solana_program::program::invoke(
            &spl_token::instruction::transfer(
                ctx.accounts.token_program.key,
                ctx.accounts.source.key,
                ctx.accounts.destination.key,
                ctx.accounts.authority.key,
                &[],
                amount,
            )?,
            &[
                ctx.accounts.source.clone(),
                ctx.accounts.destination.clone(),
                ctx.accounts.authority.clone(),
            ],
        )
    }
}

#[derive(Accounts)]
pub struct Cpi<'info> {
    source: UncheckedAccount<'info>,
    destination: UncheckedAccount<'info>,
    authority: UncheckedAccount<'info>,
    token_program: UncheckedAccount<'info>,
}
```

Зловмисник міг би легко викликати цю інструкцію та передати програму-дублікат маркера, яку він створив і контролює.
## Додавання програмної перевірки

Цю вразливість можна виправити, просто додавши кілька рядків до інструкції `cpi`, щоб перевірити, чи є відкритий ключ token_program відкритим ключем програми SPL Token.

```rust
pub fn cpi_secure(ctx: Context<Cpi>, amount: u64) -> ProgramResult {
    if &spl_token::ID != ctx.accounts.token_program.key {
        return Err(ProgramError::IncorrectProgramId);
    }
    solana_program::program::invoke(
        &spl_token::instruction::transfer(
            ctx.accounts.token_program.key,
            ctx.accounts.source.key,
            ctx.accounts.destination.key,
            ctx.accounts.authority.key,
            &[],
            amount,
        )?,
        &[
            ctx.accounts.source.clone(),
            ctx.accounts.destination.clone(),
            ctx.accounts.authority.clone(),
        ],
    )
}
```

Тепер, якщо зловмисник передає програму іншого маркера, інструкція поверне помилку `ProgramError::IncorrectProgramId`.

Залежно від програми, яку ви викликаєте за допомогою свого CPI, ви можете жорстко закодувати адресу очікуваного ідентифікатора програми або скористатися ящиком Rust програми, щоб отримати адресу програми, якщо вона доступна. У наведеному вище прикладі ящик `spl_token` надає адресу програми SPL Token.

## Використання модуля Anchor CPI

Простіший спосіб керувати програмними перевірками – використовувати модулі Anchor CPI. На [попередньому уроці](https://github.com/Unboxed-Software/solana-course/blob/main/content/anchor-cpi) ми дізналися, що Anchor може автоматично генерувати модулі CPI, щоб спростити CPI у програмі. Ці модулі також підвищують безпеку, перевіряючи відкритий ключ програми, переданий в одну з її публічних інструкцій.
Кожна програма Anchor використовує макрос `declare_id()` для визначення адреси програми. Коли модуль CPI генерується для певної програми, він використовує адресу, передану в цей макрос, як «джерело істини» та автоматично перевіряє, що всі CPI, створені за допомогою його модуля CPI, спрямовані на цей ідентифікатор програми.

Хоча за своєю суттю це не відрізняється від ручної перевірки програми, використання модулів CPI дозволяє уникнути можливості забути виконати перевірку програми або випадково ввести неправильний ідентифікатор програми під час жорсткого кодування.

Програма нижче показує приклад використання модуля CPI для програми SPL Token для виконання передачі, показаної в попередніх прикладах.
```rust
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod arbitrary_cpi_recommended {
    use super::*;

    pub fn cpi(ctx: Context<Cpi>, amount: u64) -> ProgramResult {
        token::transfer(ctx.accounts.transfer_ctx(), amount)
    }
}

#[derive(Accounts)]
pub struct Cpi<'info> {
    source: Account<'info, TokenAccount>,
    destination: Account<'info, TokenAccount>,
    authority: Signer<'info>,
    token_program: Program<'info, Token>,
}

impl<'info> Cpi<'info> {
    pub fn transfer_ctx(&self) -> CpiContext<'_, '_, '_, 'info, token::Transfer<'info>> {
        let program = self.token_program.to_account_info();
        let accounts = token::Transfer {
            from: self.source.to_account_info(),
            to: self.destination.to_account_info(),
            authority: self.authority.to_account_info(),
        };
        CpiContext::new(program, accounts)
    }
}
```

Зауважте, що, як і в прикладі вище, Anchor створив декілька [оболонок для популярних нативних програм](https://github.com/coral-xyz/anchor/tree/master/spl/src), які дозволяють видавати CPI так, ніби вони були якірними/прив'язаними програмами.

Крім того, залежно від програми, для якої ви робите CPI, ви можете використовувати Anchor [програмний тип облікового запису](https://docs.rs/anchor-lang/latest/anchor_lang/accounts/program/struct .Program.html), щоб перевірити передану програму в структурі перевірки вашого облікового запису. Між ящиками [`anchor_lang`](https://docs.rs/anchor-lang/latest/anchor_lang) та [`anchor_spl`](https://docs.rs/anchor_spl/latest/) такі типи 'Program' надаються з коробки:

- [`System`](https://docs.rs/anchor-lang/latest/anchor_lang/struct.System.html)
- [`AssociatedToken`](https://docs.rs/anchor-spl/latest/anchor_spl/associated_token/struct.AssociatedToken.html)
- [`Token`](https://docs.rs/anchor-spl/latest/anchor_spl/token/struct.Token.html)

Якщо у вас є доступ до модуля CPI програми Anchor, ви зазвичай можете імпортувати її тип програми замінивши назву програми назвою актуальної програми:

```rust
use other_program::program::OtherProgram;
```

# Лабораторія

Щоб показати важливість перевірки CPI за допомогою програми, яку ви використовуєте, ми попрацюємо зі спрощеною та дещо надуманою грою. Ця гра представляє персонажів з обліковими записами PDA (Program Derived Addresses/Похідні адреси програми) і використовує окрему програму «метаданих» для керування метаданими персонажів і такими атрибутами, як здоров’я та сила.

Хоча цей приклад є дещо надуманим, насправді це майже ідентична архітектура до того, як працюють NFT на Solana: Програма токенів SPL керує монетним двором, розповсюдженням і передачею токенів, а окрема програма метаданих використовується для призначення метаданих токенам. Тож уразливість, через яку ми проходимо тут, також може бути застосована до реальних токенів.
### 1. Налаштування

Ми почнемо з гілки `starter` [цього репозиторію](https://github.com/Unboxed-Software/solana-arbitrary-cpi/tree/starter). Клонуйте репозиторій, а потім відкрийте його в гілці `starter`.

Зверніть увагу, що існує три програми:

1. `gameplay` -ігровий процес
2. `character-metadata` -символьні метадані
3. `fake-metadata`     -хибні, або підроблені метадані

Крім того, у каталозі `tests` вже є тест.

Перша програма, `gameplay`, безпосередньо використовується в нашому тесті. Подивіться на програму. Є дві інструкції:

1. `create_character_insecure` - створює нового персонажа та CPI в програмі метаданих для встановлення початкових атрибутів персонажа
2. `battle_insecure` - протиставляє двох персонажів один одному, призначаючи «перемогу» персонажу з найвищими атрибутами

Друга програма, `character-metadata`, призначена як "схвалена" програма для обробки метаданих символів. Подивіться на цю програму. Вона має одну інструкцію для `create_metadata`, яка створює новий PDA і призначає псевдовипадкове значення від 0 до 20 для здоров’я та сили персонажа.

Остання програма, `fake-metadata`, — це програма для підроблених метаданих, призначена для ілюстрації того, що може зробити зловмисник, щоб використати нашу програму `gameplay`. Ця програма майже ідентична програмі `character-metadata`, тільки вона призначає початкове здоров’я та силу персонажа як максимально допустимі: 255.

### 2. Перевірте інструкцію `create_character_insecure`

Для цього вже є тест у каталозі `tests`. Це довго, але приділіть хвилинку, перш ніж ми обговоримо це разом:

```typescript
it("Insecure instructions allow attacker to win every time", async () => {
    // Ініціалізувати гравця один зі справжньою програмою метаданих
    await gameplayProgram.methods
      .createCharacterInsecure()
      .accounts({
        metadataProgram: metadataProgram.programId,
        authority: playerOne.publicKey,
      })
      .signers([playerOne])
      .rpc()

    // Ініціалізувати зловмисника за допомогою програми підроблених метаданих
    await gameplayProgram.methods
      .createCharacterInsecure()
      .accounts({
        metadataProgram: fakeMetadataProgram.programId,
        authority: attacker.publicKey,
      })
      .signers([attacker])
      .rpc()

    // Отримайте облікові записи метаданих обох гравців
    const [playerOneMetadataKey] = getMetadataKey(
      playerOne.publicKey,
      gameplayProgram.programId,
      metadataProgram.programId
    )

    const [attackerMetadataKey] = getMetadataKey(
      attacker.publicKey,
      gameplayProgram.programId,
      fakeMetadataProgram.programId
    )

    const playerOneMetadata = await metadataProgram.account.metadata.fetch(
      playerOneMetadataKey
    )

    const attackerMetadata = await fakeMetadataProgram.account.metadata.fetch(
      attackerMetadataKey
    )

    // Звичайний гравець повинен мати здоров'я та силу від 0 до 20
    expect(playerOneMetadata.health).to.be.lessThan(20)
    expect(playerOneMetadata.power).to.be.lessThan(20)

    // Зловмисник матиме здоров'я та силу 255
    expect(attackerMetadata.health).to.equal(255)
    expect(attackerMetadata.power).to.equal(255)
})
```

У цьому тесті розглядається сценарій, у якому звичайний гравець і зловмисник створюють своїх персонажів. Лише зловмисник передає ідентифікатор програми підроблених метаданих, а не фактичну програму метаданих. І оскільки інструкція `create_character_insecure` не має програмних перевірок, вона все одно виконується.

У результаті звичайний персонаж має відповідну кількість здоров’я та сили: кожен має значення від 0 до 20. Але здоров’я та сила атакуючого становлять 255, що робить нападника непереможним.

Якщо ви ще цього не зробили, запустіть `anchor test`, щоб переконатися, що цей тест насправді поводиться, як описано.
### 3. Створіть інструкцію `create_character_secure`

Давайте виправимо це, створивши безпечну інструкцію для створення нового персонажа. Ця інструкція має здійснювати належні перевірки програми та використовувати ящик `cpi` програми `character-metadata` для виконання CPI, а не просто використовувати `invoke`.

Якщо ви хочете перевірити свої навички, спробуйте це самостійно, перш ніж рухатися далі.

Ми почнемо з оновлення нашого оператора `use` у верхній частині файлу `lib.rs` програм `gameplay`. Ми надаємо собі доступ до типу програми для перевірки облікового запису та допоміжної функції для видачі CPI `create_metadata`.

```rust
use character_metadata::{
    cpi::accounts::CreateMetadata,
    cpi::create_metadata,
    program::CharacterMetadata,
};
```

Далі створимо нову структуру перевірки облікового запису під назвою `CreateCharacterSecure`. Цього разу ми робимо `metadata_program` типом `Program`:

```rust
#[derive(Accounts)]
pub struct CreateCharacterSecure<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 32 + 64,
        seeds = [authority.key().as_ref()],
        bump
    )]
    pub character: Account<'info, Character>,
    #[account(
        mut,
        seeds = [character.key().as_ref()],
        seeds::program = metadata_program.key(),
        bump,
    )]
    /// CHECK: manual checks
    pub metadata_account: AccountInfo<'info>,
    pub metadata_program: Program<'info, CharacterMetadata>,
    pub system_program: Program<'info, System>,
}
```

Нарешті, ми додаємо інструкцію `create_character_secure`. Він буде таким же, як і раніше, але використовуватиме повну функціональність Anchor CPI, а не використовуватиме безпосередньо `invoke`:

```rust
pub fn create_character_secure(ctx: Context<CreateCharacterSecure>) -> Result<()> {
    let character = &mut ctx.accounts.character;
    character.metadata = ctx.accounts.metadata_account.key();
    character.auth = ctx.accounts.authority.key();
    character.wins = 0;

    let context = CpiContext::new(
        ctx.accounts.metadata_program.to_account_info(),
        CreateMetadata {
            character: ctx.accounts.character.to_account_info(),
            metadata: ctx.accounts.metadata_account.to_owned(),
            authority: ctx.accounts.authority.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
        },
    );

    create_metadata(context)?;

    Ok(())
}
```

### 4.Перевірте `create_character_secure`

Тепер, коли у нас є безпечний спосіб ініціалізації нового символу, давайте створимо новий тест. У цьому тесті просто потрібно спробувати ініціалізувати персонажа зловмисника та очікувати викидання помилки.

```typescript
it("Secure character creation doesn't allow fake program", async () => {
    try {
      await gameplayProgram.methods
        .createCharacterSecure()
        .accounts({
          metadataProgram: fakeMetadataProgram.programId,
          authority: attacker.publicKey,
        })
        .signers([attacker])
        .rpc()
    } catch (error) {
      expect(error)
      console.log(error)
    }
})
```

Запустіть `anchor test`, якщо ви цього ще не зробили. Зауважте, що помилка була викинута, як і очікувалося, у якій зазначено, що ідентифікатор програми, переданий у інструкції, не є очікуваним ідентифікатором програми:

```bash
'Program log: AnchorError caused by account: metadata_program. Error Code: InvalidProgramId. Error Number: 3008. Error Message: Program ID was not as expected.',
'Program log: Left:',
'Program log: FKBWhshzcQa29cCyaXc1vfkZ5U985gD5YsqfCzJYUBr',
'Program log: Right:',
'Program log: D4hPnYEsAx4u3EQMrKEXsY3MkfLndXbBKTEYTwwm25TE'
```

Це все, що вам потрібно зробити, щоб захиститися від довільних CPI!

Бувають випадки, коли вам потрібна більша гнучкість CPI вашої програми. Звичайно, ми не будемо перешкоджати вам створювати програму, яка вам потрібна, але, будь ласка, вживайте всіх можливих заходів, щоб у вашій програмі не було вразливостей.

Якщо ви хочете поглянути на остаточний код рішення, ви можете знайти його у гілці `рішення` [того самого репозиторію](https://github.com/Unboxed-Software/solana-arbitrary-cpi/tree/solution ).

# Виклик

Як і в інших уроках цього розділу, ваша можливість потренуватися уникати цього експлойту безпеки полягає в перевірці власних або інших програм.

Виділіть деякий час, щоб переглянути принаймні одну програму та переконатися, що програмні перевірки проводяться для кожної програми, переданої в інструкції, особливо тих, які викликаються через CPI.

Пам’ятайте: якщо ви знайшли помилку чи експлойт у чиїйсь програмі, повідомте про це! Якщо ви знайшли такий у своїй програмі, обов’язково встановіть його негайно.


## Закінчив лабораторію?

Надішліть свій код на GitHub і [розкажіть нам, що ви думаєте про цей урок](https://form.typeform.com/to/IPH0UGz7#answers-lesson=5bcaf062-c356-4b58-80a0-12cca99c29b0)!
