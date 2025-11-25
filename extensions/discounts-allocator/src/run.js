import { DiscountApplicationStrategy } from "../generated/api";
import { Decimal } from "decimal.js";

/**
 * @typedef {import("../generated/api").RunInput} RunInput
 * @typedef {import("../generated/api").FunctionRunResult} FunctionRunResult
 */

export function run(input) {
  const cartLines = input.cart.lines;

  // Get customer loyalty tier
  const loyaltyTier =
    input.cart.buyerIdentity?.customer?.metafields?.loyaltylion?.loyalty_tier?.value;

  // Only apply discounts to Loyalist or Enthusiast
  if (!loyaltyTier || (loyaltyTier !== "Loyalist" && loyaltyTier !== "Enthusiast")) {
    return { discounts: [], discountApplicationStrategy: DiscountApplicationStrategy.All };
  }

  // Calculate cart subtotal in cents
  const subtotal = cartLines.reduce((sum, line) => {
    const price = parseFloat(line.cost?.amountPerQuantity?.amount ?? "0");
    return sum + price * line.quantity;
  }, 0);

  // Determine discount percentage based on subtotal
  let discountPercentage = 0;
  if (subtotal < 5000) discountPercentage = 10;
  else if (subtotal < 10000) discountPercentage = 15;
  else if (subtotal < 15000) discountPercentage = 20;
  else return { discounts: [], discountApplicationStrategy: DiscountApplicationStrategy.All }; // No discount over $150

  const discounts = [];

  for (const line of cartLines) {
    const variant = line.merchandise;
    const quantity = line.quantity;
    const originalPrice = parseFloat(line.cost?.amountPerQuantity?.amount ?? "0");
    if (!originalPrice || isNaN(originalPrice)) continue;

    // Optional: read variant/product metafields for additional adjustments
    const variantDiscountValue = variant?.metafield?.value;
    const productDiscountValue = variant?.product?.metafield?.value;
    // You can parse JSON from these if needed for extra rules
    // const discountJsonRaw = variantDiscountValue || productDiscountValue;

    const totalDiscount = new Decimal(originalPrice)
      .mul(quantity)
      .mul(discountPercentage)
      .div(100)
      .toFixed(2);

    discounts.push({
      targets: [
        {
          productVariant: {
            id: variant.id,
          },
        },
      ],
      value: {
        fixedAmount: {
          amount: totalDiscount,
        },
      },
      message: `${discountPercentage}% Loyalty Tier Discount`,
    });
  }

  return {
    discounts,
    discountApplicationStrategy: DiscountApplicationStrategy.All,
  };
}
