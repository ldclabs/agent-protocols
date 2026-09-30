// Generated from docs/protocols/agent-mail/1.0.schema.json; keep byte-for-byte equivalent as JSON.
export const MAIL_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://agent-protocols.dev/schemas/agent-mail/1.0.schema.json",
  title: "Agent Mail Protocol 1.0",
  description:
    "Structural definitions; signed objects and packets are closed, while Identity list/discovery extensions are retained. Strict I-JSON, Unicode scalar validity, canonical JCS, parsed URL origins, Ed25519 signatures, HPKE and all-zero X25519 checks, byte lengths, cross-field equality, lifetime bounds, receipt/reply binding, authorization, and stateful lifecycle requirements need semantic validation; passing this schema is not protocol conformance. Select a named definition for HTTP response objects.",
  oneOf: [
    {
      $ref: "#/$defs/envelope",
    },
    {
      $ref: "#/$defs/packet",
    },
  ],
  $defs: {
    agentId: {
      type: "string",
      pattern: "^did:agent:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$(?![\\s\\S])",
    },
    hash32: {
      type: "string",
      pattern: "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$(?![\\s\\S])",
    },
    id16: {
      type: "string",
      pattern: "^[A-Za-z0-9_-]{21}[AQgw]$(?![\\s\\S])",
    },
    signature: {
      type: "string",
      pattern: "^[A-Za-z0-9_-]{85}[AQgw]$(?![\\s\\S])",
    },
    base64url: {
      type: "string",
      pattern:
        "^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$(?![\\s\\S])",
    },
    timestampMs: {
      type: "integer",
      minimum: 0,
      maximum: 9007199254740991,
    },
    positiveSafeInteger: {
      type: "integer",
      minimum: 1,
      maximum: 9007199254740991,
    },
    httpsOrigin: {
      type: "string",
      pattern: "^https://[^/?#@\\s]+$(?![\\s\\S])",
      not: {
        pattern: ":443$(?![\\s\\S])",
      },
      description:
        "Approximate syntax only. Identity canonical HTTPS origin parsing and serialization are a semantic requirement.",
    },
    mailboxesEndpoint: {
      type: "string",
      pattern: "^https://[^/?#@\\s]+(?:/[^?#\\s]*)?$(?![\\s\\S])",
      description:
        "Semantic validation additionally requires the same canonical HTTPS origin as service, no userinfo/query/fragment/trailing slash, and valid URL parsing.",
      not: {
        pattern: "/$(?![\\s\\S])",
      },
    },
    mailboxCardPayload: {
      type: "object",
      required: [
        "mailbox_id",
        "enabled",
        "expires_at",
        "receive_until",
        "key_id",
        "public_key",
        "routes",
        "max_packet_bytes",
      ],
      properties: {
        mailbox_id: {
          $ref: "#/$defs/id16",
        },
        enabled: {
          type: "boolean",
        },
        expires_at: {
          $ref: "#/$defs/timestampMs",
        },
        receive_until: {
          $ref: "#/$defs/timestampMs",
        },
        key_id: {
          $ref: "#/$defs/id16",
        },
        public_key: {
          $ref: "#/$defs/hash32",
        },
        routes: {
          type: "array",
          items: {
            $ref: "#/$defs/httpsOrigin",
          },
          minItems: 1,
          maxItems: 8,
          uniqueItems: true,
        },
        max_packet_bytes: {
          type: "integer",
          minimum: 4096,
          maximum: 1048576,
        },
      },
      additionalProperties: false,
    },
    part: {
      type: "object",
      required: ["media_type", "data"],
      properties: {
        media_type: {
          type: "string",
          maxLength: 127,
          pattern:
            "^[a-z0-9][a-z0-9!#$&^_.+\\-]*/[a-z0-9][a-z0-9!#$&^_.+\\-]*$(?![\\s\\S])",
        },
        data: {
          $ref: "#/$defs/base64url",
        },
        name: {
          type: "string",
          minLength: 1,
          maxLength: 255,
        },
      },
      additionalProperties: false,
    },
    messagePayload: {
      type: "object",
      required: ["to", "expires_at", "thread_id", "parts"],
      properties: {
        to: {
          $ref: "#/$defs/agentId",
        },
        expires_at: {
          $ref: "#/$defs/timestampMs",
        },
        thread_id: {
          $ref: "#/$defs/id16",
        },
        parts: {
          type: "array",
          items: {
            $ref: "#/$defs/part",
          },
          minItems: 1,
          maxItems: 32,
        },
        subject: {
          type: "string",
          maxLength: 1024,
        },
        in_reply_to: {
          $ref: "#/$defs/hash32",
        },
        reply_card: {
          $ref: "#/$defs/mailboxCardEnvelope",
        },
        receipt_requested: {
          type: "boolean",
          default: false,
        },
      },
      additionalProperties: false,
    },
    receiptPayload: {
      type: "object",
      required: ["to", "expires_at", "message_hash", "status"],
      properties: {
        to: {
          $ref: "#/$defs/agentId",
        },
        expires_at: {
          $ref: "#/$defs/timestampMs",
        },
        message_hash: {
          $ref: "#/$defs/hash32",
        },
        status: {
          const: "received",
        },
      },
      additionalProperties: false,
    },
    mailboxCardEvent: {
      type: "object",
      required: ["protocol", "type", "actor", "created_at", "nonce", "payload"],
      properties: {
        protocol: {
          const: "agent-mail/1.0",
        },
        type: {
          const: "mailbox.publish",
        },
        actor: {
          $ref: "#/$defs/agentId",
        },
        created_at: {
          $ref: "#/$defs/timestampMs",
        },
        nonce: {
          $ref: "#/$defs/positiveSafeInteger",
        },
        payload: {
          $ref: "#/$defs/mailboxCardPayload",
        },
      },
      additionalProperties: false,
    },
    mailboxCardEnvelope: {
      type: "object",
      required: ["event", "hash", "signature"],
      properties: {
        event: {
          $ref: "#/$defs/mailboxCardEvent",
        },
        hash: {
          $ref: "#/$defs/hash32",
        },
        signature: {
          $ref: "#/$defs/signature",
        },
      },
      additionalProperties: false,
    },
    messageEvent: {
      type: "object",
      required: ["protocol", "type", "actor", "created_at", "nonce", "payload"],
      properties: {
        protocol: {
          const: "agent-mail/1.0",
        },
        type: {
          const: "mail.message",
        },
        actor: {
          $ref: "#/$defs/agentId",
        },
        created_at: {
          $ref: "#/$defs/timestampMs",
        },
        nonce: {
          $ref: "#/$defs/positiveSafeInteger",
        },
        payload: {
          $ref: "#/$defs/messagePayload",
        },
      },
      additionalProperties: false,
    },
    messageEnvelope: {
      type: "object",
      required: ["event", "hash", "signature"],
      properties: {
        event: {
          $ref: "#/$defs/messageEvent",
        },
        hash: {
          $ref: "#/$defs/hash32",
        },
        signature: {
          $ref: "#/$defs/signature",
        },
      },
      additionalProperties: false,
    },
    receiptEvent: {
      type: "object",
      required: ["protocol", "type", "actor", "created_at", "nonce", "payload"],
      properties: {
        protocol: {
          const: "agent-mail/1.0",
        },
        type: {
          const: "mail.receipt",
        },
        actor: {
          $ref: "#/$defs/agentId",
        },
        created_at: {
          $ref: "#/$defs/timestampMs",
        },
        nonce: {
          $ref: "#/$defs/positiveSafeInteger",
        },
        payload: {
          $ref: "#/$defs/receiptPayload",
        },
      },
      additionalProperties: false,
    },
    receiptEnvelope: {
      type: "object",
      required: ["event", "hash", "signature"],
      properties: {
        event: {
          $ref: "#/$defs/receiptEvent",
        },
        hash: {
          $ref: "#/$defs/hash32",
        },
        signature: {
          $ref: "#/$defs/signature",
        },
      },
      additionalProperties: false,
    },
    letterEnvelope: {
      oneOf: [
        {
          $ref: "#/$defs/messageEnvelope",
        },
        {
          $ref: "#/$defs/receiptEnvelope",
        },
      ],
    },
    envelope: {
      oneOf: [
        {
          $ref: "#/$defs/mailboxCardEnvelope",
        },
        {
          $ref: "#/$defs/messageEnvelope",
        },
        {
          $ref: "#/$defs/receiptEnvelope",
        },
      ],
    },
    packetHeader: {
      type: "object",
      required: ["protocol", "mailbox_id", "card_hash", "key_id", "expires_at"],
      properties: {
        protocol: {
          const: "agent-mail/1.0",
        },
        mailbox_id: {
          $ref: "#/$defs/id16",
        },
        card_hash: {
          $ref: "#/$defs/hash32",
        },
        key_id: {
          $ref: "#/$defs/id16",
        },
        expires_at: {
          $ref: "#/$defs/timestampMs",
        },
      },
      additionalProperties: false,
    },
    packet: {
      type: "object",
      required: ["header", "enc", "ciphertext"],
      properties: {
        header: {
          $ref: "#/$defs/packetHeader",
        },
        enc: {
          $ref: "#/$defs/hash32",
        },
        ciphertext: {
          allOf: [
            {
              $ref: "#/$defs/base64url",
            },
          ],
          minLength: 1387,
          maxLength: 1048576,
          description:
            "Decoded length must be >= 1040 and 16 modulo 1024. Total JCS(packet) length must fit the card and protocol limits; these are semantic checks.",
        },
      },
      additionalProperties: false,
    },
    cardAcceptedRecord: {
      type: "object",
      required: ["envelope", "accepted_at"],
      properties: {
        envelope: {
          $ref: "#/$defs/mailboxCardEnvelope",
        },
        accepted_at: {
          $ref: "#/$defs/timestampMs",
        },
      },
      additionalProperties: false,
    },
    deliveryResult: {
      type: "object",
      required: ["packet_id", "accepted_at", "seq"],
      properties: {
        packet_id: {
          $ref: "#/$defs/hash32",
        },
        accepted_at: {
          $ref: "#/$defs/timestampMs",
        },
        seq: {
          $ref: "#/$defs/positiveSafeInteger",
        },
      },
      additionalProperties: false,
    },
    packetRecord: {
      type: "object",
      required: ["packet_id", "packet", "accepted_at", "seq"],
      properties: {
        packet_id: {
          $ref: "#/$defs/hash32",
        },
        packet: {
          $ref: "#/$defs/packet",
        },
        accepted_at: {
          $ref: "#/$defs/timestampMs",
        },
        seq: {
          $ref: "#/$defs/positiveSafeInteger",
        },
      },
      additionalProperties: false,
    },
    packetList: {
      type: "object",
      required: ["result"],
      properties: {
        result: {
          type: "array",
          items: {
            $ref: "#/$defs/packetRecord",
          },
          minItems: 0,
          maxItems: 1000,
        },
        next_cursor: {
          type: "string",
          minLength: 1,
        },
      },
      additionalProperties: true,
    },
    discoveryDocument: {
      type: "object",
      required: ["protocol", "service"],
      properties: {
        protocol: {
          const: "agent-mail/1.0",
        },
        service: {
          $ref: "#/$defs/httpsOrigin",
        },
        endpoints: {
          type: "object",
          required: [],
          properties: {
            mailboxes: {
              $ref: "#/$defs/mailboxesEndpoint",
            },
          },
          additionalProperties: false,
        },
        features: {
          type: "array",
          items: {
            type: "string",
          },
          uniqueItems: true,
        },
      },
      additionalProperties: true,
    },
  },
} as const;
