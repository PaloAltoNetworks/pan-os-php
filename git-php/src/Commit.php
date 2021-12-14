<?php

	namespace CzProject\GitPhp;


	class Commit
	{
		/** @var CommitId */
		private $id;

		/** @var string */
		private $subject;

		/** @var string|NULL */
		private $body;

		/** @var string */
		private $authorEmail;

		/** @var string|NULL */
		private $authorName;

		/** @var \DateTimeImmutable */
		private $authorDate;

		/** @var string */
		private $committerEmail;

		/** @var string|NULL */
		private $committerName;

		/** @var \DateTimeImmutable */
		private $committerDate;


		/**
		 * @param string $subject
		 * @param string|NULL $body
		 * @param string $authorEmail
		 * @param string|NULL $authorName
		 * @param string $committerEmail
		 * @param string|NULL $committerName
		 */
		public function __construct(
			CommitId $id,
			$subject,
			$body,
			$authorEmail,
			$authorName,
			\DateTimeImmutable $authorDate,
			$committerEmail,
			$committerName,
			\DateTimeImmutable $committerDate
		)
		{
			$this->id = $id;
			$this->subject = $subject;
			$this->body = $body;
			$this->authorEmail = $authorEmail;
			$this->authorName = $authorName;
			$this->authorDate = $authorDate;
			$this->committerEmail = $committerEmail;
			$this->committerName = $committerName;
			$this->committerDate = $committerDate;
		}


		/**
		 * @return CommitId
		 */
		public function getId()
		{
			return $this->id;
		}


		/**
		 * @return string
		 */
		public function getSubject()
		{
			return $this->subject;
		}


		/**
		 * @return string|NULL
		 */
		public function getBody()
		{
			return $this->body;
		}


		/**
		 * @return string|NULL
		 */
		public function getAuthorName()
		{
			return $this->authorName;
		}


		/**
		 * @return string
		 */
		public function getAuthorEmail()
		{
			return $this->authorEmail;
		}


		/**
         * @return string
		 */
		//* @return \DateTimeImmutable
		public function getAuthorDate( $format = 'Y-m-d H:i:s' )
		{
			return $this->authorDate->format($format );
		}


		/**
		 * @return string|NULL
		 */
		public function getCommitterName()
		{
			return $this->committerName;
		}


		/**
		 * @return string
		 */
		public function getCommitterEmail()
		{
			return $this->committerEmail;
		}


		/**
         * @return string
		 */
		//* @return \DateTimeImmutable
		public function getCommitterDate( $format = 'Y-m-d H:i:s' )
		{
			return $this->committerDate->format($format );
		}


		/**
		 * Alias for getAuthorDate()
         * * @return string
		 */
		//* @return \DateTimeImmutable
		public function getDate( $format = 'Y-m-d H:i:s' )
		{
			return $this->authorDate;
		}
	}
