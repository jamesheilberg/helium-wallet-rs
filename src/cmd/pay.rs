use crate::{
    cmd::{
        api_url, get_password, get_txn_fees, load_wallet, print_footer, print_json, print_table,
        status_json, status_str, Opts, OutputFormat,
    },
    keypair::PubKeyBin,
    result::Result,
    traits::{Sign, TxnEnvelope, TxnFee, B58, B64},
};
use helium_api::{
    Account, BlockchainTxn, BlockchainTxnPaymentV2, Client, Hnt, Payment, PendingTxnStatus,
};
use prettytable::Table;
use serde_json::json;
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
/// Send one or more payments to given addresses. Note that HNT only
/// goes to 8 decimals of precision. The payment is not submitted to
/// the system unless the '--commit' option is given.
pub struct Cmd {
    /// Address and amount of HNT to send in <address>=<amount> format.
    #[structopt(long = "payee", short = "p", name = "payee=hnt", required = true)]
    payees: Vec<Payee>,

    /// Optionally set how many minutes in the future oracle prices should be considered for
    /// Set to 0 for "optimistic" submission with current price
    #[structopt(long, default_value = "120")]
    oracle_window: u64,

    /// Manually set DC fee to pay for the transaction
    #[structopt(long)]
    fee: Option<u64>,

    /// Commit the payment to the API
    #[structopt(long)]
    commit: bool,
}

impl Cmd {
    pub fn run(&self, opts: Opts) -> Result {
        let password = get_password(false)?;
        let wallet = load_wallet(opts.files)?;

        let client = Client::new_with_base_url(api_url());

        let keypair = wallet.decrypt(password.as_bytes())?;
        let account = client.get_account(&keypair.public.to_b58()?)?;

        let mut sweep_destination = None;
        let mut pay_total = 0;

        let payments: Result<Vec<Payment>> = self
            .payees
            .iter()
            .map(|p| {
                let amount = if let Amount::HNT(amount) = p.amount {
                    let amount = amount.to_bones();
                    pay_total += amount;
                    amount
                } else if sweep_destination.is_none() {
                    sweep_destination = Some(PubKeyBin::from_b58(&p.address)?.to_vec());
                    0
                } else {
                    panic!("Cannot sweep to two addresses in the same transaction!")
                };

                Ok(Payment {
                    payee: PubKeyBin::from_b58(&p.address)?.into(),
                    amount,
                })
            })
            .collect();
        let mut txn = BlockchainTxnPaymentV2 {
            fee: 0,
            payments: payments?,
            payer: keypair.pubkey_bin().into(),
            nonce: account.speculative_nonce + 1,
            signature: Vec::new(),
        };

        txn.fee = if let Some(fee) = self.fee {
            // if fee is set by hand, sweep calculation is non-iterative
            // simply calculate_sweep once and set as payment to sweep_destination addr
            if let Some(sweep_destination) = sweep_destination {
                let amount = calculate_remaining_hnt(
                    &client,
                    &account,
                    &pay_total,
                    &txn.fee,
                    &self.oracle_window,
                )?;
                for payment in &mut txn.payments {
                    if payment.payee == sweep_destination {
                        payment.amount = amount;
                    }
                }
            }
            fee
        } else {
            // if fee is set by hand, sweep calculation becomes iterative
            // because the size of the transaction depends on the sweep amount
            if let Some(sweep_destination) = sweep_destination {
                let mut fee = txn.txn_fee(&get_txn_fees(&client)?)?;
                loop {
                    let sweep_amount = calculate_remaining_hnt(
                        &client,
                        &account,
                        &pay_total,
                        &fee,
                        &self.oracle_window,
                    )?;
                    for payment in &mut txn.payments {
                        if payment.payee == sweep_destination {
                            payment.amount = sweep_amount;
                        }
                    }
                    let new_fee = txn.txn_fee(&get_txn_fees(&client)?)?;
                    if new_fee == fee {
                        break;
                    } else {
                        fee = new_fee;
                    }
                }
                fee
            } else {
                txn.txn_fee(&get_txn_fees(&client)?)?
            }
        };

        txn.signature = txn.sign(&keypair)?;
        let envelope = txn.in_envelope();
        let status = if self.commit {
            Some(client.submit_txn(&envelope)?)
        } else {
            None
        };

        print_txn(&txn, &envelope, &status, opts.format)
    }
}

fn print_txn(
    txn: &BlockchainTxnPaymentV2,
    envelope: &BlockchainTxn,
    status: &Option<PendingTxnStatus>,
    format: OutputFormat,
) -> Result {
    match format {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.add_row(row!["Payee", "Amount"]);
            for payment in txn.payments.clone() {
                table.add_row(row![
                    PubKeyBin::from_vec(&payment.payee).to_b58().unwrap(),
                    Hnt::from_bones(payment.amount)
                ]);
            }
            print_table(&table)?;

            ptable!(
                ["Key", "Value"],
                ["Fee", txn.fee],
                ["Nonce", txn.nonce],
                ["Hash", status_str(status)]
            );

            print_footer(status)
        }
        OutputFormat::Json => {
            let mut payments = Vec::with_capacity(txn.payments.len());
            for payment in txn.payments.clone() {
                payments.push(json!({
                    "payee": PubKeyBin::from_vec(&payment.payee).to_b58().unwrap(),
                    "amount": Hnt::from_bones(payment.amount),
                }))
            }
            let table = json!({
                "payments": payments,
                "fee": txn.fee,
                "nonce": txn.nonce,
                "hash": status_json(status),
                "txn": envelope.to_b64()?,
            });
            print_json(&table)
        }
    }
}

#[derive(Debug)]
pub struct Payee {
    address: String,
    amount: Amount,
}

#[derive(Debug)]
enum Amount {
    HNT(Hnt),
    Sweep,
}

impl std::str::FromStr for Amount {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(if s == "sweep" {
            Amount::Sweep
        } else {
            Amount::HNT(Hnt::from_str(s)?)
        })
    }
}

impl FromStr for Payee {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let pos = s
            .find('=')
            .ok_or_else(|| format!("invalid KEY=value: missing `=`  in `{}`", s))?;
        Ok(Payee {
            address: s[..pos].to_string(),
            amount: s[pos + 1..].parse()?,
        })
    }
}

fn calculate_remaining_hnt(
    client: &helium_api::Client,
    account: &Account,
    pay_total: &u64,
    fee: &u64,
    oracle_window: &u64,
) -> Result<u64> {
    use rust_decimal::{prelude::ToPrimitive, Decimal};
    use std::convert::TryInto;
    use std::time::{SystemTime, UNIX_EPOCH};

    // if account has the DCs for the charge,
    // the sweep is simply the remaining balance after payment to others
    if &account.dc_balance > fee {
        Ok(account.balance - pay_total)
    }
    // otherwise, we need to leave enough HNT to pay the txn fee via implicit burn
    else {
        // if window == 0, simply return the current price
        let oracle_price = if *oracle_window == 0 {
            client.get_oracle_price_current()?
        }
        // else, use the oracle_window, give in minutes to select max price
        else {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
            let mut oracle_prices = client.get_oracle_price_predictions()?;
            // filter down predictions that are not in window
            oracle_prices.retain(|prediction| {
                let prediction_time = prediction.time as u64;
                // sometimes API may be lagging real time, so if prediction is already passed
                // retain this value
                if prediction_time < now.as_secs() {
                    true
                } else {
                    // true if prediction time is within window
                    prediction_time - now.as_secs() < oracle_window * 60
                }
            });

            // take max of all predictions
            oracle_prices
                .iter()
                .fold(client.get_oracle_price_current()?, |max, x| {
                    if max.get_decimal() < x.price.get_decimal() {
                        x.price
                    } else {
                        max
                    }
                })
        };

        // fee was given in DC, which is $ 10^-5
        // express the decimal in $
        let fee = Decimal::new((*fee).try_into()?, 5);
        // simple decimal division tells you the amount of HNT needed
        let mut hnt_needed = fee / oracle_price.get_decimal();
        // change scale by 8 decimals - we want to implicit burn fee in bones
        hnt_needed.set_scale(hnt_needed.scale() - 8)?;
        // ceil rounds up for us and change into u64 for txn building
        let bones_needed = hnt_needed.ceil().to_u64().unwrap();
        Ok(account.balance - pay_total - bones_needed)
    }
}
