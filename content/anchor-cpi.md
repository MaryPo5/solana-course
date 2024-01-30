---
заголовок: Прив’язка CPI та помилки
цілі:
- Зробіть перехресні виклики програм (CPI) з програми прив'язки
- Використовуйте функцію `cpi` для створення допоміжних функцій для виклику інструкцій у існуючих програмах Anchor
- Використовуйте `invoke` та `invoke_signed`, щоб створити CPI там, де допоміжні функції CPI недоступні
- Створення та повернення власних помилок Anchor
---

# Багато тексту

- Anchor забезпечує спрощений спосіб створення CPI за допомогою **`CpiContext`**
- Функція Anchor **`cpi`** генерує допоміжні функції CPI для виклику інструкцій у існуючих програмах Anchor.
- Якщо ви не маєте доступу до допоміжних функцій CPI, ви все ще можете безпосередньо використовувати `invoke` і `invoke_signed`
- Макрос атрибута **`error_code`** використовується для створення спеціальних помилок прив’язки

# Огляд

Якщо ви згадаєте [перший урок CPI] (cpi), то пам’ятаєте, що побудова CPI може бути складною з vanilla Rust. Однак Anchor робить це трохи простіше, особливо якщо програма, яку ви викликаєте, також є програмою Anchor, до ящика якої ви можете отримати доступ.

У цьому уроці ви дізнаєтеся, як побудувати опорний CPI. Ви також дізнаєтесь, як видавати власні помилки з програми Anchor, щоб почати писати більш складні програми Anchor.

## Міжпрограмні виклики (CPI) з Anchor

Щоб відновити увагу, CPI дозволяють програмам викликати інструкції в інших програмах за допомогою функцій `invoke` або `invoke_signed`. Це дозволяє створювати нові програми на основі існуючих програм (ми називаємо це компонуванням).

Хоча створення CPI безпосередньо за допомогою `invoke` або `invoke_signed` все ще є можливістю, Anchor також надає спрощений спосіб створення CPI за допомогою `CpiContext`.

У цьому уроці ви використовуватимете ящик `anchor_spl`, щоб створити CPI для програми токенів SPL. Ви можете [дослідити, що доступно в ящику `anchor_spl`](https://docs.rs/anchor-spl/latest/anchor_spl/#).

### `CpiContext`

Першим кроком у створенні CPI є створення екземпляра `CpiContext`. `CpiContext` дуже схожий на `Context`, перший тип аргументу, необхідний для функцій інструкцій Anchor. Вони обидва оголошені в тому самому модулі та мають однакову функціональність.

Тип `CpiContext` визначає вхідні дані без аргументів для міжпрограмних викликів:

- `accounts` - список облікових записів, необхідних для виклику інструкції
- `remaining_accounts` - усі облікові записи, що залишилися
- `program` - ідентифікатор програми, яка викликається
- `signer_seeds` - якщо підписується PDA, включіть початкові числа, необхідні для похідного PDA

```rust
pub struct CpiContext<'a, 'b, 'c, 'info, T>
where
    T: ToAccountMetas + ToAccountInfos<'info>,
{
    pub accounts: T,
    pub remaining_accounts: Vec<AccountInfo<'info>>,
    pub program: AccountInfo<'info>,
    pub signer_seeds: &'a [&'b [&'c [u8]]],
}
```

Ви використовуєте `CpiContext::new` для створення нового екземпляра під час передачі оригінального підпису транзакції.

```rust
CpiContext::new(cpi_program, cpi_accounts)
```

```rust
pub fn new(
        program: AccountInfo<'info>,
        accounts: T
    ) -> Self {
    Self {
        accounts,
        program,
        remaining_accounts: Vec::new(),
        signer_seeds: &[],
    }
}
```

Ви використовуєте `CpiContext::new_with_signer` для створення нового екземпляра під час підписання від імені PDA для CPI.

```rust
CpiContext::new_with_signer(cpi_program, cpi_accounts, seeds)
```

```rust
pub fn new_with_signer(
    program: AccountInfo<'info>,
    accounts: T,
    signer_seeds: &'a [&'b [&'c [u8]]],
) -> Self {
    Self {
        accounts,
        program,
        signer_seeds,
        remaining_accounts: Vec::new(),
    }
}
```

### облікові записи CPI

Одна з головних особливостей `CpiContext`, яка спрощує міжпрограмні виклики, полягає в тому, що аргумент `accounts` є загальним типом, який дозволяє передавати будь-який об’єкт, який приймає властивості `ToAccountMetas` і `ToAccountInfos<'info>`».

Ці ознаки додаються за допомогою макросу атрибута #[derive(Accounts)]`, який ви використовували раніше під час створення структур для представлення облікових записів інструкцій. Це означає, що ви можете використовувати подібні структури з `CpiContext`.

Це допомагає з організацією коду та безпекою типів.

### Викликати інструкцію в іншій програмі Anchor

Якщо програма, яку ви викликаєте, є програмою Anchor з опублікованою коробкою, Anchor може генерувати для вас конструктори інструкцій і допоміжні функції CPI.

Просто оголосіть залежність вашої програми від програми, яку ви викликаєте, у файлі `Cargo.toml` вашої програми наступним чином:

```
[dependencies]
callee = { path = "../callee", features = ["cpi"]}
```

Додавши `features = ["cpi"]`, ви вмикаєте функцію `cpi`, і ваша програма отримує доступ до модуля `callee::cpi`.

Модуль `cpi` надає інструкції `callee` як функцію Rust, яка приймає як аргументи `CpiContext` та будь-які додаткові дані інструкцій. Ці функції використовують той самий формат, що й функції інструкцій у ваших програмах Anchor, тільки з `CpiContext` замість `Context`. Модуль `cpi` також надає структури облікових записів, необхідні для виклику інструкцій.

Наприклад, якщо `callee` має інструкцію `do_something`, яка вимагає облікових записів, визначених у структурі `DoSomething`, ви можете викликати `do_something` наступним чином:

```rust
use anchor_lang::prelude::*;
use callee;
...

#[program]
pub mod lootbox_program {
    use super::*;

    pub fn call_another_program(ctx: Context<CallAnotherProgram>, params: InitUserParams) -> Result<()> {
        callee::cpi::do_something(
            CpiContext::new(
                ctx.accounts.callee.to_account_info(),
                callee::DoSomething {
                    user: ctx.accounts.user.to_account_info()
                }
            )
        )
        Ok(())
    }
}
...
```

### Викликати інструкцію в програмі, яка не є прив’язкою (non-Anchor)

Якщо програма, яку ви викликаєте, *non* є Anchor програма, є два можливі варіанти:

1. Цілком можливо, що розробники програми опублікували ящик із власними допоміжними функціями для виклику своєї програми. Наприклад, ящик `anchor_spl` надає допоміжні функції, які практично ідентичні з точки зору сайту виклику тим, що ви отримаєте з модулем `cpi` програми Anchor. наприклад ви можете мінтити/карбувати за допомогою допоміжної функції [`mint_to`](https://docs.rs/anchor-spl/latest/src/anchor_spl/token.rs.html#36-58) і використовувати структуру облікових записів [`MintTo` ](https://docs.rs/anchor-spl/latest/anchor_spl/token/struct.MintTo.html).
    ```rust
    token::mint_to(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::MintTo {
                mint: ctx.accounts.mint_account.to_account_info(),
                to: ctx.accounts.token_account.to_account_info(),
                authority: ctx.accounts.mint_authority.to_account_info(),
            },
            &[&[
                "mint".as_bytes(),
                &[*ctx.bumps.get("mint_authority").unwrap()],
            ]]
        ),
        amount,
    )?;
    ```
2. Якщо немає допоміжного модуля для програми, чиї інструкції(и) потрібно викликати, ви можете повернутися до використання `invoke` та `invoke_signed`. Фактично, вихідний код допоміжної функції `mint_to`, згаданий вище, демонструє приклад використання `invoke_signed`, коли надається `CpiContext`. Ви можете дотримуватися подібної моделі, якщо вирішите використовувати структуру облікових записів і `CpiContext` для організації та підготовки свого CPI.
    ```rust
    pub fn mint_to<'a, 'b, 'c, 'info>(
        ctx: CpiContext<'a, 'b, 'c, 'info, MintTo<'info>>,
        amount: u64,
    ) -> Result<()> {
        let ix = spl_token::instruction::mint_to(
            &spl_token::ID,
            ctx.accounts.mint.key,
            ctx.accounts.to.key,
            ctx.accounts.authority.key,
            &[],
            amount,
        )?;
        solana_program::program::invoke_signed(
            &ix,
            &[
                ctx.accounts.to.clone(),
                ctx.accounts.mint.clone(),
                ctx.accounts.authority.clone(),
            ],
            ctx.signer_seeds,
        )
        .map_err(Into::into)
    }
    ```

## Викликання помилок в Anchor.

На даний момент ми достатньо глибоко занурилися в Anchor, тому важливо знати, як створювати власні помилки.

Зрештою, усі програми повертають однаковий тип помилки: [`ProgramError`](https://docs.rs/solana-program/latest/solana_program/program_error/enum.ProgramError.html). Однак під час написання програми за допомогою Anchor ви можете використовувати `AnchorError` як абстракцію поверх `ProgramError`. Ця абстракція надає додаткову інформацію, коли програма виходить з ладу, зокрема:

- Назва та номер помилки
- Місце в коді, де виникла помилка
- Обліковий запис, який порушив обмеження

```rust
pub struct AnchorError {
    pub error_name: String,
    pub error_code_number: u32,
    pub error_msg: String,
    pub error_origin: Option<ErrorOrigin>,
    pub compared_values: Option<ComparedValues>,
}
```

Anchor Errors можна розділити на:

- Anchor Internal Errors, внутрішні помилки, які фреймворк повертає з власного коду
- Custom errors, cпеціальні помилки, які ви можете створити як розробник

Ви можете додати помилки, унікальні для вашої програми, використовуючи атрибут `error_code`. Просто додайте цей атрибут до спеціального типу `enum`. Потім ви можете використовувати варіанти `enum` як помилки у своїй програмі. Крім того, ви можете додати повідомлення про помилку до кожного варіанту за допомогою атрибута `msg`. У разі виникнення помилки клієнти можуть відобразити це повідомлення про помилку.

```rust
#[error_code]
pub enum MyError {
    #[msg("MyAccount may only hold data below 100")]
    DataTooLarge
}
```

Щоб повернути спеціальну помилку, ви можете скористатися [err](https://docs.rs/anchor-lang/latest/anchor_lang/macro.err.html) або [error](https://docs.rs/anchor -lang/latest/anchor_lang/prelude/macro.error.html) макрос із функції інструкції. Вони додають інформацію про файл і рядок до помилки, яка потім реєструється Anchor, щоб допомогти вам з налагодженням.

```rust
#[program]
mod hello_anchor {
    use super::*;
    pub fn set_data(ctx: Context<SetData>, data: MyAccount) -> Result<()> {
        if data.data >= 100 {
            return err!(MyError::DataTooLarge);
        }
        ctx.accounts.my_account.set_inner(data);
        Ok(())
    }
}

#[error_code]
pub enum MyError {
    #[msg("MyAccount may only hold data below 100")]
    DataTooLarge
}
```

Крім того, ви можете використати макрос [require](https://docs.rs/anchor-lang/latest/anchor_lang/macro.require.html), щоб спростити повернення помилок. Наведений вище код можна змінити на такий:

```rust
#[program]
mod hello_anchor {
    use super::*;
    pub fn set_data(ctx: Context<SetData>, data: MyAccount) -> Result<()> {
        require!(data.data < 100, MyError::DataTooLarge);
        ctx.accounts.my_account.set_inner(data);
        Ok(())
    }
}

#[error_code]
pub enum MyError {
    #[msg("MyAccount may only hold data below 100")]
    DataTooLarge
}
```

# Лабораторія

Давайте відпрацюємо концепції, які ми розглянули на цьому уроці, спираючись на програму  Movie Review /Огляд фільмів із попередніх уроків.

У цій лабораторії ми оновимо програму, щоб мінтити/карбувати токени користувачам, коли вони надсилають рецензію на новий фільм.

### 1.Стартер

Для початку ми використаємо остаточний стан програми Anchor Movie Review з попереднього уроку. Отже, якщо ви щойно пройшли цей урок, усе готово. Якщо ви тільки починаєте, не хвилюйтеся, ви можете [завантажити початковий код](https://github.com/Unboxed-Software/anchor-movie-review-program/tree/solution-pdas). Ми будемо використовувати гілку `solution-pdas` як нашу відправну точку.

### 2. Додайте залежності до `Cargo.toml`

Перш ніж почати, нам потрібно ввімкнути функцію `init-if-needed` і додати ящик `anchor-spl` до залежностей у `Cargo.toml`. Якщо вам потрібно оновити функцію `init-if-needed`, подивіться на [урок Anchor PDAs and Accounts](anchor-pdas).

```rust
[dependencies]
anchor-lang = { version = "0.25.0", features = ["init-if-needed"] }
anchor-spl = "0.25.0"
```

### 3. Ініціалізувати токен винагороди

Далі перейдіть до `lib.rs` і створіть інструкцію для ініціалізації нового токена. Це буде маркер, який карбується кожного разу, коли користувач залишає відгук. Зауважте, що нам не потрібно включати будь-яку спеціальну логіку інструкцій, оскільки ініціалізація може бути оброблена повністю через обмеження Anchor.

```rust
pub fn initialize_token_mint(_ctx: Context<InitializeMint>) -> Result<()> {
    msg!("Token mint initialized");
    Ok(())
}
```

Тепер реалізуйте тип контексту `InitializeMint` і перелічіть облікові записи та обмеження, яких вимагає інструкція. Тут ми ініціалізуємо новий обліковий запис `Mint` за допомогою PDA з рядком "mint" як початковим. Зауважте, що ми можемо використовувати той самий КПК як для адреси облікового запису `Mint`, так і для адреси монетного двору. Використання PDA як органу монетного двору дозволяє нашій програмі підписувати карбування токенів.

Щоб ініціалізувати обліковий запис `Mint`, нам потрібно буде включити `token_program`, `rent` і `system_program` до списку облікових записів.

```rust
#[derive(Accounts)]
pub struct InitializeMint<'info> {
    #[account(
        init,
        seeds = ["mint".as_bytes()],
        bump,
        payer = user,
        mint::decimals = 6,
        mint::authority = mint,
    )]
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
    pub system_program: Program<'info, System>
}
```

Вище можуть бути деякі обмеження, яких ви ще не бачили. Додавання `mint::decimals` і `mint::authority` разом з `init` гарантує, що обліковий запис буде ініціалізовано як новий токен монетного двору з відповідним набором десяткових знаків і повноважень монетного двору.

### 4. Anchor Error/Помилка прив'язки

Далі створимо  Anchor Error, яку ми використовуватимемо під час перевірки `rating`, переданого в інструкції `add_movie_review` або `update_movie_review`.
```rust
#[error_code]
enum MovieReviewError {
    #[msg("Rating must be between 1 and 5")]
    InvalidRating
}
```

### 5.Оновлення інструкції `add_movie_review`

Тепер, коли ми виконали деякі налаштування, давайте оновимо інструкцію `add_movie_review` і тип контексту `AddMovieReview`, щоб карбувати маркери для рецензента.

Далі оновіть тип контексту `AddMovieReview`, щоб додати такі облікові записи:

- `token_program` - ми будемо використовувати програму Token для карбування жетонів
- `mint` - обліковий запис монетного двору для жетонів, які ми будемо карбувати користувачам, коли вони додадуть огляд фільму
- `token_account` - пов'язаний обліковий запис токена для вищезгаданого `mint` та рецензента
- `associated_token_program` - необхідний, оскільки ми будемо використовувати обмеження `associated_token` для `token_account`
- `rent` - необхідний, оскільки ми використовуємо обмеження `init-if-needed` для `token_account`
- 
```rust
#[derive(Accounts)]
#[instruction(title: String, description: String)]
pub struct AddMovieReview<'info> {
    #[account(
        init,
        seeds=[title.as_bytes(), initializer.key().as_ref()],
        bump,
        payer = initializer,
        space = 8 + 32 + 1 + 4 + title.len() + 4 + description.len()
    )]
    pub movie_review: Account<'info, MovieAccountState>,
    #[account(mut)]
    pub initializer: Signer<'info>,
    pub system_program: Program<'info, System>,
    // ДОДАНІ ОБЛІКОВІ ЗАПИСИ НИЖЧЕ
    pub token_program: Program<'info, Token>,
    #[account(
        seeds = ["mint".as_bytes()]
        bump,
        mut
    )]
    pub mint: Account<'info, Mint>,
    #[account(
        init_if_needed,
        payer = initializer,
        associated_token::mint = mint,
        associated_token::authority = initializer
    )]
    pub token_account: Account<'info, TokenAccount>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub rent: Sysvar<'info, Rent>
}
```

Знову ж таки, деякі з наведених вище обмежень можуть бути вам незнайомі. Обмеження `associated_token::mint` і `associated_token::authority` разом із обмеженням `init_if_needed` гарантують, що якщо обліковий запис ще не ініціалізовано, він буде ініціалізований як пов’язаний обліковий запис маркера для вказаного монетного двору та повноваження.

Далі оновимо інструкцію `add_movie_review`, щоб зробити наступне:

- Перевірте, чи `rating` дійсний. Якщо це недійсний рейтинг, поверніть помилку `InvalidRating`.
- Зробіть CPI для інструкції `mint_to` програми-токена, використовуючи PDA для монетного двору як підписувача. Зауважте, що ми будемо карбувати 10 токенів для користувача, але нам потрібно налаштувати десяткові знаки монетного двору, зробивши їх «10*10^6».

На щастя, ми можемо використовувати ящик `anchor_spl` для доступу до допоміжних функцій і типів, таких як `mint_to` і `MintTo`, для створення нашого CPI для програми маркерів. `mint_to` приймає `CpiContext` і ціле число як аргументи, де ціле число представляє кількість токенів для карбування. `MintTo` можна використовувати для списку облікових записів, які потрібні інструкції монетного двору.

```rust
pub fn add_movie_review(ctx: Context<AddMovieReview>, title: String, description: String, rating: u8) -> Result<()> {
    msg!("Movie review account created");
    msg!("Title: {}", title);
    msg!("Description: {}", description);
    msg!("Rating: {}", rating);

    require!(rating >= 1 && rating <= 5, MovieReviewError::InvalidRating);

    let movie_review = &mut ctx.accounts.movie_review;
    movie_review.reviewer = ctx.accounts.initializer.key();
    movie_review.title = title;
    movie_review.description = description;
    movie_review.rating = rating;

    mint_to(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                authority: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.token_account.to_account_info(),
                mint: ctx.accounts.mint.to_account_info()
            },
            &[&[
                "mint".as_bytes(),
                &[*ctx.bumps.get("mint").unwrap()]
            ]]
        ),
        10*10^6
    )?;

    msg!("Minted tokens");

    Ok(())
}
```

### 6. Оновлення інструкції `update_movie_review`

Тут ми лише додаємо перевірку правильності `rating`.
```rust
pub fn update_movie_review(ctx: Context<UpdateMovieReview>, title: String, description: String, rating: u8) -> Result<()> {
    msg!("Movie review account space reallocated");
    msg!("Title: {}", title);
    msg!("Description: {}", description);
    msg!("Rating: {}", rating);

    require!(rating >= 1 && rating <= 5, MovieReviewError::InvalidRating);

    let movie_review = &mut ctx.accounts.movie_review;
    movie_review.description = description;
    movie_review.rating = rating;

    Ok(())
}
```

### 7. Тест

Це всі зміни, які нам потрібно внести в програму! Тепер давайте оновимо наші тести.

Почніть із того, що ваш імпорт і функція `describe` виглядають так:

```typescript
import * as anchor from "@project-serum/anchor"
import { Program } from "@project-serum/anchor"
import { expect } from "chai"
import { getAssociatedTokenAddress, getAccount } from "@solana/spl-token"
import { AnchorMovieReviewProgram } from "../target/types/anchor_movie_review_program"

describe("anchor-movie-review-program", () => {
  // Налаштуйте клієнт для використання локального кластера.
  const provider = anchor.AnchorProvider.env()
  anchor.setProvider(provider)

  const program = anchor.workspace
    .AnchorMovieReviewProgram as Program<AnchorMovieReviewProgram>

  const movie = {
    title: "Just a test movie",
    description: "Wow what a good movie it was real great",
    rating: 5,
  }

  const [movie_pda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from(movie.title), provider.wallet.publicKey.toBuffer()],
    program.programId
  )

  const [mint] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("mint")],
    program.programId
  )
...
}
```

Зробивши це, додайте тест для інструкції `initializeTokenMint`:

```typescript
it("Initializes the reward token", async () => {
    const tx = await program.methods.initializeTokenMint().rpc()
})
```

Зауважте, що нам не потрібно було додавати `.accounts`, тому що вони викликають висновок, включаючи обліковий запис `mint` (припускаючи, що у вас увімкнено початковий висновок).

Далі оновіть тест для інструкції `addMovieReview`. Основними доповненнями є:
1. Щоб отримати пов’язану адресу маркера, яку потрібно передати в інструкцію як обліковий запис, який не можна визначити
2. Наприкінці тесту перевірте, чи пов’язаний обліковий запис токенів має 10 токенів

```typescript
it("Movie review is added`", async () => {
  const tokenAccount = await getAssociatedTokenAddress(
    mint,
    provider.wallet.publicKey
  )
  
  const tx = await program.methods
    .addMovieReview(movie.title, movie.description, movie.rating)
    .accounts({
      tokenAccount: tokenAccount,
    })
    .rpc()
  
  const account = await program.account.movieAccountState.fetch(movie_pda)
  expect(movie.title === account.title)
  expect(movie.rating === account.rating)
  expect(movie.description === account.description)
  expect(account.reviewer === provider.wallet.publicKey)

  const userAta = await getAccount(provider.connection, tokenAccount)
  expect(Number(userAta.amount)).to.equal((10 * 10) ^ 6)
})
```

Після цього ні тест для `updateMovieReview`, ні тест для `deleteMovieReview` не потребують змін.

На цьому етапі запустіть `anchor test`, і ви повинні побачити наступний результат

```console
anchor-movie-review-program
    ✔ Initializes the reward token (458ms)
    ✔ Movie review is added (410ms)
    ✔ Movie review is updated (402ms)
    ✔ Deletes a movie review (405ms)

  5 passing (2s)
```

Якщо вам потрібно більше часу з концепціями цього уроку або ви застрягли на цьому шляху, не соромтеся перегляньте [код рішення](https://github.com/Unboxed-Software/anchor-movie-review-program /tree/solution-add-tokens). Зауважте, що рішення для цієї лабораторії знаходиться у гілці `solution-add-tokens`.

# Виклик

Щоб застосувати те, що ви дізналися про CPI на цьому уроці, подумайте про те, як ви можете включити їх у програму Intro для студентів. Ви можете зробити щось подібне до того, що ми робили в лабораторії тут, і додати певну функціональність до монетизації токенів для користувачів, коли вони представляють себе.

Спробуйте зробити це самостійно, якщо можете! Але якщо ви застрягли, сміливо посилайтеся на цей [код рішення](https://github.com/Unboxed-Software/anchor-student-intro-program/tree/cpi-challenge). Зауважте, що ваш код може дещо відрізнятися від коду рішення залежно від вашої реалізації.


## Закінчив лабораторію?

Надішліть свій код на GitHub і [розкажіть нам, що ви думаєте про цей урок](https://form.typeform.com/to/IPH0UGz7#answers-lesson=21375c76-b6f1-4fb6-8cc1-9ef151bc5b0a)!
